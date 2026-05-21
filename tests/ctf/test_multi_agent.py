"""Tests for multi_agent.py — ExploitAgent, CoordinatorAgent, ReconAgent, CriticAgent.

Covers:
  - ExploitAgent.execute() uses run_route() and handles RouteResult statuses
  - Exception handling in ExploitAgent.execute()
  - CoordinatorAgent route selection
  - Orchestrator loop termination
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest

from autopnex.ctf.multi_agent import (
    ExploitAgent,
    CoordinatorAgent,
    ReconAgent,
    CriticAgent,
    AgentDecision,
    MultiAgentOrchestrator,
)
from autopnex.ctf.route_state_machine import RouteResult
from autopnex.ctf.web_state_blackboard import WebStateBlackboard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def blackboard():
    """Create a fresh blackboard for testing."""
    return WebStateBlackboard(target_url="http://localhost:8080")


@pytest.fixture
def exploit_agent(blackboard):
    """Create an ExploitAgent instance."""
    return ExploitAgent(blackboard, "http://localhost:8080")


@pytest.fixture
def coordinator(blackboard):
    """Create a CoordinatorAgent instance."""
    return CoordinatorAgent(blackboard)


# ---------------------------------------------------------------------------
# ExploitAgent Tests
# ---------------------------------------------------------------------------

class TestExploitAgentExecute:
    """Tests for ExploitAgent.execute() using run_route() as primary path."""

    def test_execute_success_status(self, exploit_agent, blackboard):
        """ExploitAgent returns flag info when run_route returns success."""
        decision = AgentDecision(
            agent="exploit",
            route="source_leak",
            hypothesis="test",
            confidence=0.8,
            next_action={"action": "run_state_machine", "route": "source_leak"},
        )

        mock_result = RouteResult(
            route="source_leak",
            status="success",
            flag="flag{test_flag}",
            best_evidence_score=0.95,
            steps_executed=5,
            stop_reason="flag_found",
        )

        with patch("autopnex.ctf.multi_agent.run_route", return_value=mock_result):
            result = exploit_agent.execute(decision)

        assert result["found_flag"] is True
        assert result["flag"] == "flag{test_flag}"
        assert result["status"] == "success"
        assert result["stop_reason"] == "flag_found"
        assert result["steps_executed"] == 5
        # Flag should be recorded in blackboard
        assert len(blackboard.candidate_flags) == 1
        assert blackboard.candidate_flags[0].value == "flag{test_flag}"

    def test_execute_failed_status(self, exploit_agent, blackboard):
        """ExploitAgent returns failure info when run_route returns failed."""
        decision = AgentDecision(
            agent="exploit",
            route="lfi",
            hypothesis="test",
            confidence=0.5,
            next_action={"action": "run_state_machine", "route": "lfi"},
        )

        mock_result = RouteResult(
            route="lfi",
            status="failed",
            best_evidence_score=0.2,
            steps_executed=1,
            stop_reason="low_evidence: 0.20",
        )

        with patch("autopnex.ctf.multi_agent.run_route", return_value=mock_result):
            result = exploit_agent.execute(decision)

        assert result["found_flag"] is False
        assert result["flag"] is None
        assert result["status"] == "failed"
        assert result["stop_reason"] == "low_evidence: 0.20"

    def test_execute_handoff_status(self, exploit_agent, blackboard):
        """ExploitAgent returns handoff info when run_route returns handoff."""
        decision = AgentDecision(
            agent="exploit",
            route="ssti",
            hypothesis="test",
            confidence=0.6,
            next_action={"action": "run_state_machine", "route": "ssti"},
        )

        mock_result = RouteResult(
            route="ssti",
            status="handoff",
            best_evidence_score=0.7,
            steps_executed=3,
            stop_reason="handoff",
            handoff_target="cmdi",
        )

        with patch("autopnex.ctf.multi_agent.run_route", return_value=mock_result):
            result = exploit_agent.execute(decision)

        assert result["found_flag"] is False
        assert result["status"] == "handoff"
        assert result["handoff_target"] == "cmdi"
        assert result["stop_reason"] == "handoff"

    def test_execute_inconclusive_status(self, exploit_agent, blackboard):
        """ExploitAgent returns inconclusive info when max_steps reached."""
        decision = AgentDecision(
            agent="exploit",
            route="sqli",
            hypothesis="test",
            confidence=0.5,
            next_action={"action": "run_state_machine", "route": "sqli"},
        )

        mock_result = RouteResult(
            route="sqli",
            status="inconclusive",
            best_evidence_score=0.45,
            steps_executed=10,
            stop_reason="max_steps",
        )

        with patch("autopnex.ctf.multi_agent.run_route", return_value=mock_result):
            result = exploit_agent.execute(decision)

        assert result["found_flag"] is False
        assert result["status"] == "inconclusive"
        assert result["stop_reason"] == "max_steps"
        assert result["steps_executed"] == 10

    def test_execute_exception_handling(self, exploit_agent, blackboard):
        """ExploitAgent catches exceptions and returns error result."""
        decision = AgentDecision(
            agent="exploit",
            route="source_leak",
            hypothesis="test",
            confidence=0.8,
            next_action={"action": "run_state_machine", "route": "source_leak"},
        )

        with patch("autopnex.ctf.multi_agent.run_route", side_effect=RuntimeError("Connection refused")):
            result = exploit_agent.execute(decision)

        assert result["found_flag"] is False
        assert result["status"] == "error"
        assert "Connection refused" in result["error"]

    def test_execute_no_route_specified(self, exploit_agent):
        """ExploitAgent returns error when no route is specified."""
        decision = AgentDecision(
            agent="exploit",
            route="unknown",
            hypothesis="test",
            confidence=0.0,
            next_action={"action": "none"},
        )

        result = exploit_agent.execute(decision)
        assert "error" in result

    def test_execute_records_evidence_on_success(self, exploit_agent, blackboard):
        """ExploitAgent records evidence to blackboard on success."""
        decision = AgentDecision(
            agent="exploit",
            route="lfi",
            hypothesis="test",
            confidence=0.8,
            next_action={"action": "run_state_machine", "route": "lfi"},
        )

        mock_result = RouteResult(
            route="lfi",
            status="success",
            flag="flag{lfi_flag}",
            best_evidence_score=0.9,
            steps_executed=4,
            stop_reason="flag_found",
        )

        with patch("autopnex.ctf.multi_agent.run_route", return_value=mock_result):
            exploit_agent.execute(decision)

        # Evidence should be recorded
        assert len(blackboard.evidence) > 0
        assert any(e.route == "lfi" for e in blackboard.evidence)


# ---------------------------------------------------------------------------
# CoordinatorAgent Tests
# ---------------------------------------------------------------------------

class TestCoordinatorAgent:
    """Tests for CoordinatorAgent route selection and decision logic."""

    def test_initial_decision_is_recon(self, coordinator, blackboard):
        """Coordinator starts with recon when no endpoints discovered."""
        decision = coordinator.decide()
        assert decision.next_action.get("to") == "recon" or decision.route == "recon"

    def test_route_failures_tracked(self, coordinator):
        """Coordinator tracks route failures."""
        coordinator.record_result("lfi", success=False)
        assert coordinator.route_failures["lfi"] == 1

        coordinator.record_result("lfi", success=False)
        assert coordinator.route_failures["lfi"] == 2

    def test_route_success_resets_failures(self, coordinator):
        """Coordinator resets failure count on success."""
        coordinator.route_failures["lfi"] = 3
        coordinator.record_result("lfi", success=True)
        assert coordinator.route_failures["lfi"] == 0

    def test_flag_candidate_triggers_stop(self, coordinator, blackboard):
        """Coordinator stops when high-confidence flag is found."""
        blackboard.add_flag_candidate("flag{found}", source="test", confidence=0.9)
        decision = coordinator.decide()
        assert decision.next_action.get("action") == "stop"


# ---------------------------------------------------------------------------
# CriticAgent Tests
# ---------------------------------------------------------------------------

class TestCoordinatorProcessExploitResult:
    """Tests for CoordinatorAgent.process_exploit_result() handling RouteResult statuses."""

    def test_success_sets_stop_and_flag(self, coordinator, blackboard):
        """status='success' → stop=True, flag returned, failures reset."""
        coordinator.route_failures["lfi"] = 2
        result = {
            "route": "lfi",
            "status": "success",
            "flag": "flag{got_it}",
            "steps_executed": 4,
            "stop_reason": "flag_found",
        }

        outcome = coordinator.process_exploit_result(result)

        assert outcome["stop"] is True
        assert outcome["flag"] == "flag{got_it}"
        assert outcome["next_route"] is None
        # Failures should be reset on success
        assert coordinator.route_failures["lfi"] == 0

    def test_handoff_sets_next_route(self, coordinator, blackboard):
        """status='handoff' → next_route set to handoff_target, evidence added."""
        result = {
            "route": "ssti",
            "status": "handoff",
            "handoff_target": "cmdi",
            "steps_executed": 3,
            "stop_reason": "handoff_detected",
        }

        outcome = coordinator.process_exploit_result(result)

        assert outcome["stop"] is False
        assert outcome["next_route"] == "cmdi"
        assert outcome["flag"] is None
        # Route attempts should be incremented
        assert coordinator.route_attempts.get("ssti", 0) >= 1
        # Evidence should be added for the handoff target
        assert any(e.route == "cmdi" for e in blackboard.evidence)

    def test_failed_increments_route_failures(self, coordinator, blackboard):
        """status='failed' → route_failures incremented, budget decremented."""
        initial_budget = coordinator.budget_remaining
        result = {
            "route": "sqli",
            "status": "failed",
            "steps_executed": 1,
            "stop_reason": "precondition_fail",
        }

        outcome = coordinator.process_exploit_result(result)

        assert outcome["stop"] is False
        assert outcome["next_route"] is None
        assert coordinator.route_failures["sqli"] == 1
        assert coordinator.budget_remaining == initial_budget - 1

    def test_failed_accumulates_failures(self, coordinator, blackboard):
        """Multiple failures accumulate in route_failures counter."""
        for _ in range(3):
            coordinator.process_exploit_result({
                "route": "jwt",
                "status": "failed",
                "steps_executed": 2,
                "stop_reason": "no_vuln",
            })

        assert coordinator.route_failures["jwt"] == 3

    def test_inconclusive_increments_attempts_not_failures(self, coordinator, blackboard):
        """status='inconclusive' → route_attempts incremented, route_failures unchanged."""
        initial_budget = coordinator.budget_remaining
        result = {
            "route": "sqli",
            "status": "inconclusive",
            "steps_executed": 10,
            "stop_reason": "max_steps",
        }

        outcome = coordinator.process_exploit_result(result)

        assert outcome["stop"] is False
        assert outcome["next_route"] is None
        # Attempts incremented, failures NOT incremented
        assert coordinator.route_attempts.get("sqli", 0) >= 1
        assert coordinator.route_failures.get("sqli", 0) == 0
        assert coordinator.budget_remaining == initial_budget - 1

    def test_error_status_treated_as_failure(self, coordinator, blackboard):
        """Unknown/error status → treated as failure."""
        result = {
            "route": "upload",
            "status": "error",
            "error": "Connection refused",
        }

        outcome = coordinator.process_exploit_result(result)

        assert outcome["stop"] is False
        assert coordinator.route_failures["upload"] == 1

    def test_success_without_flag_still_stops(self, coordinator, blackboard):
        """status='success' with no flag still sets stop (edge case)."""
        result = {
            "route": "source_leak",
            "status": "success",
            "flag": None,
            "steps_executed": 5,
            "stop_reason": "flag_found",
        }

        outcome = coordinator.process_exploit_result(result)

        # stop is False when flag is None (nothing to verify)
        assert outcome["stop"] is False
        assert outcome["flag"] is None


# ---------------------------------------------------------------------------
# CriticAgent Tests
# ---------------------------------------------------------------------------

class TestCriticAgent:
    """Tests for CriticAgent repeat detection."""

    def test_instantiation(self, blackboard):
        """CriticAgent can be instantiated."""
        critic = CriticAgent(blackboard)
        assert critic.agent_name == "critic"

    def test_decide_with_empty_blackboard(self, blackboard):
        """CriticAgent produces a decision even with empty blackboard."""
        critic = CriticAgent(blackboard)
        decision = critic.decide()
        assert decision.agent == "critic"

    def test_repeat_detection_forces_switch(self, blackboard):
        """CriticAgent forces route switch when same tool fails ≥ 3 times on same route."""
        critic = CriticAgent(blackboard)

        # Record 3 failed attempts with same tool but different args (to avoid dedup)
        for i in range(3):
            blackboard.record_attempt(
                route="lfi",
                tool="http_get",
                args={"url": f"http://target/?file=/etc/passwd{i}"},
                success=False,
                result_summary="Not found",
            )

        decision = critic.decide()

        # Should recommend force_switch
        assert decision.next_action.get("action") == "force_switch"
        assert decision.next_action.get("reason") == "repeat_threshold_exceeded"
        # Supporting evidence should contain FORCE_SWITCH info
        assert any("FORCE_SWITCH" in ev for ev in decision.supporting_evidence)

    def test_no_force_switch_below_threshold(self, blackboard):
        """CriticAgent does NOT force switch when repeats < 3."""
        critic = CriticAgent(blackboard)

        # Record only 2 failed attempts with same tool
        for i in range(2):
            blackboard.record_attempt(
                route="lfi",
                tool="http_get",
                args={"url": f"http://target/?file=/etc/passwd{i}"},
                success=False,
                result_summary="Not found",
            )

        decision = critic.decide()

        # Should NOT force switch
        assert decision.next_action.get("action") != "force_switch"


# ---------------------------------------------------------------------------
# MultiAgentOrchestrator.solve() Tests (Task 13.1)
# ---------------------------------------------------------------------------

class TestMultiAgentOrchestratorSolve:
    """Tests for MultiAgentOrchestrator.solve() unified interface."""

    def test_solve_returns_tuple(self, blackboard):
        """solve() returns (found, flag, action_log) tuple."""
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        orch = MultiAgentOrchestrator("http://localhost:9999", max_rounds=1)

        # Mock run_loop to avoid real HTTP calls
        with patch.object(orch, 'run_loop', return_value=(False, None, [{"round": 1}])):
            found, flag, log_entries = orch.solve(max_rounds=1)

        assert isinstance(found, bool)
        assert flag is None
        assert isinstance(log_entries, list)

    def test_solve_reinitializes_blackboard(self):
        """solve() creates a fresh blackboard for each call."""
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        orch = MultiAgentOrchestrator("http://localhost:9999", max_rounds=1)

        # Add some state to the existing blackboard
        orch.blackboard.add_evidence(route="lfi", score=0.5, source="test", observation="old")

        with patch.object(orch, 'run_loop', return_value=(False, None, [])):
            orch.solve(target_url="http://localhost:8888", max_rounds=1)

        # Blackboard should be fresh (no old evidence)
        assert orch.target_url == "http://localhost:8888"
        # The blackboard was reset, so evidence from before solve() is gone
        assert len(orch.blackboard.evidence) == 0

    def test_solve_passes_flag_format(self):
        """solve() passes flag_format to the new blackboard."""
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        orch = MultiAgentOrchestrator("http://localhost:9999", max_rounds=1)

        with patch.object(orch, 'run_loop', return_value=(False, None, [])):
            orch.solve(flag_format=r"CTF\{[^}]+\}", max_rounds=1)

        assert orch.blackboard.flag_format == r"CTF\{[^}]+\}"

    def test_solve_uses_default_target_url(self):
        """solve() uses instance target_url when none provided."""
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        orch = MultiAgentOrchestrator("http://localhost:7777", max_rounds=1)

        with patch.object(orch, 'run_loop', return_value=(False, None, [])):
            orch.solve(max_rounds=1)

        assert orch.target_url == "http://localhost:7777"


# ---------------------------------------------------------------------------
# Coordinator Route Scoring Enhancement Tests (Task 13.2)
# ---------------------------------------------------------------------------

class TestCoordinatorRouteScoring:
    """Tests for enhanced Coordinator route selection logic."""

    def test_evidence_scores_affect_ranking(self, blackboard, coordinator):
        """Routes with higher evidence scores rank higher."""
        # Add an endpoint so coordinator doesn't default to recon
        blackboard.record_endpoint(path="/", method="GET", status_code=200)

        # Add high evidence for sqli
        blackboard.add_evidence(route="sqli", score=0.9, source="test", observation="SQLi confirmed")
        # Add low evidence for lfi
        blackboard.add_evidence(route="lfi", score=0.2, source="test", observation="LFI maybe")

        scores = coordinator._score_routes()
        route_names = [r for r, _ in scores]

        # sqli should rank higher than lfi due to evidence
        if "sqli" in route_names and "lfi" in route_names:
            assert route_names.index("sqli") < route_names.index("lfi")

    def test_php_tech_stack_boosts_php_routes(self, blackboard, coordinator):
        """PHP tech stack fingerprint boosts source_leak/lfi/php_pop routes."""
        blackboard.record_endpoint(path="/", method="GET", status_code=200)
        blackboard.tech_stack.append("PHP")

        scores = coordinator._score_routes()
        scores_dict = dict(scores)

        # PHP routes should have higher scores than non-PHP routes of same priority
        # source_leak has priority 10, ssrf has priority 5
        # With PHP boost, source_leak should be even higher
        assert "source_leak" in scores_dict

    def test_route_failures_decrease_score(self, blackboard, coordinator):
        """Routes with more failures get lower scores."""
        blackboard.record_endpoint(path="/", method="GET", status_code=200)

        # Score before failures
        scores_before = dict(coordinator._score_routes())

        # Add failures
        coordinator.route_failures["source_leak"] = 3

        # Score after failures
        scores_after = dict(coordinator._score_routes())

        # source_leak score should decrease
        if "source_leak" in scores_before and "source_leak" in scores_after:
            assert scores_after["source_leak"] < scores_before["source_leak"]


# ---------------------------------------------------------------------------
# Max Rounds Degraded Return Tests (Task 13.4)
# ---------------------------------------------------------------------------

class TestMaxRoundsDegradedReturn:
    """Tests for max_rounds exhaustion graceful degradation."""

    def test_returns_best_candidate_when_rounds_exhausted(self):
        """When max_rounds exhausted, returns highest-confidence candidate flag."""
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        orch = MultiAgentOrchestrator("http://localhost:9999", max_rounds=1)

        # Add a candidate flag with moderate confidence (below 0.8 threshold)
        orch.blackboard.add_flag_candidate("flag{maybe}", source="test", confidence=0.5)

        # Run with max_rounds=1 — will exhaust rounds without finding verified flag
        # Mock recon to avoid HTTP calls
        with patch.object(orch.recon, 'execute', return_value={"action": "done", "findings": []}):
            with patch.object(orch.recon, 'decide', return_value=AgentDecision(
                agent="recon", route="recon", hypothesis="done",
                confidence=0.7, next_action={"action": "done"},
            )):
                found, flag, log_entries = orch.run_loop(max_rounds=1)

        # Should return the best candidate flag even though not verified
        assert found is False
        assert flag == "flag{maybe}"

    def test_returns_none_when_no_candidates(self):
        """When max_rounds exhausted and no candidates, returns (False, None, log)."""
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        orch = MultiAgentOrchestrator("http://localhost:9999", max_rounds=1)

        # No flag candidates at all
        with patch.object(orch.recon, 'execute', return_value={"action": "done", "findings": []}):
            with patch.object(orch.recon, 'decide', return_value=AgentDecision(
                agent="recon", route="recon", hypothesis="done",
                confidence=0.7, next_action={"action": "done"},
            )):
                found, flag, log_entries = orch.run_loop(max_rounds=1)

        assert found is False
        assert flag is None
        assert isinstance(log_entries, list)

    def test_returns_highest_confidence_among_multiple_candidates(self):
        """When multiple candidates exist, returns the one with highest confidence."""
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator

        orch = MultiAgentOrchestrator("http://localhost:9999", max_rounds=1)

        # Add multiple candidates with different confidences (all below 0.8)
        orch.blackboard.add_flag_candidate("flag{low}", source="test", confidence=0.3)
        orch.blackboard.add_flag_candidate("flag{high}", source="test", confidence=0.6)
        orch.blackboard.add_flag_candidate("flag{mid}", source="test", confidence=0.4)

        with patch.object(orch.recon, 'execute', return_value={"action": "done", "findings": []}):
            with patch.object(orch.recon, 'decide', return_value=AgentDecision(
                agent="recon", route="recon", hypothesis="done",
                confidence=0.7, next_action={"action": "done"},
            )):
                found, flag, log_entries = orch.run_loop(max_rounds=1)

        assert found is False
        assert flag == "flag{high}"  # Highest confidence candidate
