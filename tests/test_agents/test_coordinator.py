"""Coordinator: dispatch, phase ordering, and empty task list handling."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from autopnex.agents.coordinator import Coordinator, PHASE_ORDER, PHASE_AGENT_MAP
from autopnex.agents.base import AgentResult, AgentStatus, BaseAgent
from autopnex.agents.blackboard import Blackboard
from autopnex.state_machine.findings import StateFindings
from config.settings import RuntimeConfig


def _make_mock_agent(name: str) -> BaseAgent:
    agent = MagicMock(spec=BaseAgent)
    agent.name = name
    agent.execute = AsyncMock(
        return_value=AgentResult(
            agent_name=name,
            status=AgentStatus.DONE,
            tasks_completed=1,
            tasks_failed=0,
            duration_ms=10,
        )
    )
    return agent


@pytest.fixture()
def coordinator_env():
    sf = StateFindings(target="http://testhost")
    sf.add_parameter("http://testhost/search", "q", "GET")
    sf.add_finding(
        __import__("autopnex.state_machine.findings", fromlist=["Finding"]).Finding(
            title="SQLi in q",
            severity="HIGH",
            status="confirmed",
            category="sqli",
            url="http://testhost/search",
            parameter="q",
            payload="' OR 1=1--",
        )
    )
    bb = Blackboard(sf)
    config = RuntimeConfig(exploit_enabled=True, approved_scopes=("exploit",))

    agents = {}
    for agent_name in PHASE_AGENT_MAP.values():
        agents[agent_name] = _make_mock_agent(agent_name)

    coord = Coordinator(bb, agents, config=config)
    return coord, agents, bb


def test_coordinator_dispatches_to_correct_agents(coordinator_env):
    coord, agents, bb = coordinator_env
    asyncio.run(coord.run_pipeline("http://testhost"))

    for phase, agent_name in PHASE_AGENT_MAP.items():
        if phase == "REPORT":
            continue
        agents[agent_name].execute.assert_called_once()


def test_phase_ordering():
    assert PHASE_ORDER == ("RECON", "SCAN", "VULN_DETECT", "EXPLOIT", "REPORT")


def test_phase_ordering_matches_agent_map():
    for phase in PHASE_ORDER:
        assert phase in PHASE_AGENT_MAP


def test_empty_task_list_handling():
    sf = StateFindings(target="http://testhost")
    bb = Blackboard(sf)
    config = RuntimeConfig()

    report_agent = _make_mock_agent("ReportAgent")
    agents = {"ReportAgent": report_agent}

    events = []
    coord = Coordinator(
        bb, agents, config=config, progress_callback=events.append
    )
    asyncio.run(coord.run_pipeline("http://testhost"))

    event_types = [e["event"] for e in events]
    assert "pipeline_start" in event_types
    assert "pipeline_done" in event_types
    skip_events = [e for e in events if e["event"] == "phase_skip"]
    assert len(skip_events) >= 3


def test_coordinator_handles_missing_agent_gracefully():
    sf = StateFindings(target="http://testhost")
    bb = Blackboard(sf)
    config = RuntimeConfig()

    events = []
    coord = Coordinator(bb, {}, config=config, progress_callback=events.append)
    asyncio.run(coord.run_pipeline("http://testhost"))

    skip_events = [e for e in events if e["event"] == "phase_skip"]
    assert len(skip_events) == len(PHASE_ORDER)
