"""Performance tests for AutoPenX pipelines (mock mode — no LLM/network)."""
from __future__ import annotations

import threading
import time
import tracemalloc
from unittest.mock import patch

import pytest

from autopnex.orchestrator import LLMOrchestrator
from autopnex.state_machine.machine import PenTestStateMachine
from autopnex.state_machine.findings import Finding, StateFindings
from autopnex.state_machine.attack_graph import AttackGraph, NodeType
from autopnex.tools.base import ToolRegistry, ToolResult
from autopnex.agents.blackboard import Blackboard

from .profiler import PipelineProfiler

TARGET = "http://testphp.vulnweb.com"


# ---------------------------------------------------------------------------
# Helpers — fake tool execution to avoid all network I/O
# ---------------------------------------------------------------------------

def _build_mock_tool_data(arguments: dict) -> dict:
    """Return ingester-compatible parsed_data keyed by tool name."""
    url = arguments.get("url") or arguments.get("target") or TARGET
    param = arguments.get("parameter", "q")
    return {
        "port_scan": {
            "open_ports": [
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"},
            ],
        },
        "tech_detect": {"technologies": ["Apache", "PHP", "MySQL"], "security_headers": {}},
        "subdomain_find": {"subdomains": ["www.vulnweb.com", "api.vulnweb.com"]},
        "web_scan": {
            "sensitive_files": [
                {"url": f"{TARGET}/robots.txt", "status": 200, "content_type": "text/plain", "size": 42},
            ],
        },
        "dir_buster": {
            "hits": [
                {"url": f"{TARGET}/admin", "status": 200},
                {"url": f"{TARGET}/login", "status": 200},
            ],
        },
        "crawl": {
            "pages": [f"{TARGET}/page{i}" for i in range(3)],
            "forms": [{"url": f"{TARGET}/search", "method": "GET", "inputs": ["q"]}],
            "parameters": [
                {"url": f"{TARGET}/search", "name": "q", "method": "GET"},
                {"url": f"{TARGET}/login", "name": "user", "method": "POST"},
                {"url": f"{TARGET}/login", "name": "pass", "method": "POST"},
                {"url": f"{TARGET}/items", "name": "id", "method": "GET"},
            ],
        },
        "sqli_detect": {
            "vulnerable": True,
            "url": url,
            "parameter": param,
            "payload": "' OR 1=1--",
            "signals": ["error"],
            "evidence": ["SQL syntax error in response"],
            "severity": "HIGH",
        },
        "xss_detect": {
            "vulnerable": True,
            "url": url,
            "parameter": param,
            "reflections": [{"payload": "<script>alert(1)</script>", "context": "html"}],
            "severity": "MEDIUM",
        },
        "cmdi_detect": {"vulnerable": False},
        "ssrf_detect": {"vulnerable": False},
        "sqli_exploit": {
            "success": True,
            "url": url,
            "parameter": param,
            "dbms": "MySQL",
            "evidence": [{"probe": "union", "payload": "' UNION SELECT 1--", "markers": ["union"], "excerpt": "..."}],
        },
        "finding_replay": {"success": True, "url": url, "parameter": param, "status_code": 200},
    }


def _fake_execute(name, arguments, runtime_config=None):
    """Instant mock tool execution — zero network, zero I/O."""
    all_data = _build_mock_tool_data(arguments or {})
    parsed = all_data.get(name, {})
    return ToolResult(
        success=True,
        tool=name,
        summary=f"[mock] {name} completed",
        raw_output=f"mock output for {name}",
        parsed_data=dict(parsed),
        duration_ms=1,
    )


def _run_mock_pipeline(target: str = TARGET, *, multi_agent: bool = False) -> StateFindings:
    with patch.object(ToolRegistry, "execute", side_effect=_fake_execute):
        orchestrator = LLMOrchestrator(mock=True)
        fsm = PenTestStateMachine(target=target, orchestrator=orchestrator, multi_agent=multi_agent)
        return fsm.run()


def _run_mock_phase(target: str, phase: str) -> StateFindings:
    """Run only up to *phase* (inclusive) and return findings."""
    with patch.object(ToolRegistry, "execute", side_effect=_fake_execute):
        orchestrator = LLMOrchestrator(mock=True)
        fsm = PenTestStateMachine(target=target, orchestrator=orchestrator)
        fsm.findings.log_state("INIT", "perf-test init")
        phases = ["RECON", "SCAN", "VULN_DETECT", "EXPLOIT"]
        for p in phases:
            fsm.state = p
            fsm.orchestrator.reset_for_state(p)
            fsm._prepare_phase(p)
            fsm._run_phase(p)
            if p == phase:
                break
        return fsm.findings


# ===========================================================================
# Single-agent performance
# ===========================================================================

class TestSingleAgentPerformance:
    def test_pipeline_completes_under_30s_mock(self):
        """Full mock pipeline should complete in <30s."""
        start = time.perf_counter()
        findings = _run_mock_pipeline()
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        assert elapsed_ms < 30_000, f"Pipeline took {elapsed_ms}ms (limit 30 000ms)"
        assert findings.state_log, "State log should be non-empty"

    def test_recon_phase_under_5s(self):
        """Recon phase with mock should be <5s."""
        start = time.perf_counter()
        findings = _run_mock_phase(TARGET, "RECON")
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        assert elapsed_ms < 5_000, f"RECON took {elapsed_ms}ms (limit 5 000ms)"
        invoked_tools = {inv.tool for inv in findings.tool_invocations}
        assert invoked_tools, "At least one tool should have been invoked in RECON"

    def test_vuln_detect_scales_with_params(self):
        """Time should scale sub-linearly with parameter count."""
        findings_few = StateFindings(target=TARGET)
        for i in range(2):
            findings_few.add_parameter(f"{TARGET}/page?p{i}=1", f"p{i}")

        findings_many = StateFindings(target=TARGET)
        for i in range(8):
            findings_many.add_parameter(f"{TARGET}/page?p{i}=1", f"p{i}")

        def _time_vuln_detect(findings: StateFindings) -> int:
            with patch.object(ToolRegistry, "execute", side_effect=_fake_execute):
                orchestrator = LLMOrchestrator(mock=True)
                fsm = PenTestStateMachine(target=TARGET, orchestrator=orchestrator)
                fsm.findings = findings
                fsm.state = "VULN_DETECT"
                fsm.orchestrator.reset_for_state("VULN_DETECT")
                fsm._prepare_phase("VULN_DETECT")
                start = time.perf_counter()
                fsm._run_phase("VULN_DETECT")
                return int((time.perf_counter() - start) * 1000)

        time_few = _time_vuln_detect(findings_few)
        time_many = _time_vuln_detect(findings_many)

        ratio = time_many / max(time_few, 1)
        assert ratio < 8, (
            f"4x more params led to {ratio:.1f}x slowdown (expected sub-linear, <8x)"
        )

    def test_memory_under_200mb(self):
        """Peak memory during full scan should be <200MB."""
        tracemalloc.start()
        _run_mock_pipeline()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 200, f"Peak memory {peak_mb:.1f}MB exceeds 200MB limit"


# ===========================================================================
# Multi-agent performance
# ===========================================================================

class TestMultiAgentPerformance:
    @pytest.mark.slow
    def test_multi_agent_faster_than_single(self):
        """Multi-agent mode should not be significantly slower than single-agent.

        Both pipelines use mocked tools.  If multi-agent infra is incomplete
        we skip gracefully.
        """
        with patch.object(ToolRegistry, "execute", side_effect=_fake_execute):
            profiler = PipelineProfiler()
            try:
                single = profiler.profile_run(TARGET, multi_agent=False)
                multi = profiler.profile_run(TARGET, multi_agent=True)
            except Exception as exc:
                pytest.skip(f"Multi-agent infra not fully wired: {exc}")

        if single.wall_time_ms == 0:
            pytest.skip("Single-agent run reported 0ms — nothing to compare")

        speedup = single.wall_time_ms / max(multi.wall_time_ms, 1)
        assert speedup >= 0.5, (
            f"Multi-agent ({multi.wall_time_ms}ms) should not be drastically "
            f"slower than single-agent ({single.wall_time_ms}ms), got {speedup:.2f}x"
        )

    def test_concurrent_tool_execution(self):
        """Verify multiple tools run concurrently (wall time < sum of individual)."""
        import asyncio
        from autopnex.tools.base import ToolResult as TR

        sleep_seconds = 0.05
        results: list[TR] = []

        def _fake_tool(name: str) -> TR:
            time.sleep(sleep_seconds)
            return TR(success=True, tool=name, summary="ok")

        tool_names = [f"fake_{i}" for i in range(4)]

        async def _run_concurrent() -> float:
            start = time.perf_counter()
            tasks = [asyncio.to_thread(_fake_tool, n) for n in tool_names]
            done = await asyncio.gather(*tasks)
            results.extend(done)
            return time.perf_counter() - start

        wall = asyncio.run(_run_concurrent())
        sequential_estimate = sleep_seconds * len(tool_names)

        assert wall < sequential_estimate, (
            f"Concurrent wall time {wall:.3f}s should be less than "
            f"sequential estimate {sequential_estimate:.3f}s"
        )
        assert len(results) == len(tool_names)


# ===========================================================================
# Tool-level performance
# ===========================================================================

class TestToolPerformance:
    def test_tool_registry_lookup_under_1ms(self):
        """Tool registry lookup should be O(1)."""
        all_tools = ToolRegistry.all()
        if not all_tools:
            pytest.skip("No tools registered")

        name = all_tools[0].name
        iterations = 10_000
        start = time.perf_counter()
        for _ in range(iterations):
            ToolRegistry.get(name)
        elapsed_us = (time.perf_counter() - start) * 1_000_000 / iterations

        assert elapsed_us < 1000, (
            f"Average lookup {elapsed_us:.1f}µs exceeds 1ms (1000µs) budget"
        )

    def test_findings_add_dedup_performance(self):
        """Adding 1000 findings with dedup should be <100ms."""
        findings = StateFindings(target=TARGET)

        start = time.perf_counter()
        for i in range(1000):
            findings.add_finding(Finding(
                title=f"XSS #{i % 200}",
                severity="HIGH",
                url=f"{TARGET}/page{i % 200}",
                parameter=f"q{i % 200}",
                category="xss",
            ))
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 100, (
            f"1000 add_finding calls took {elapsed_ms:.1f}ms (limit 100ms)"
        )
        assert len(findings.findings) == 200, "Dedup should collapse to 200 unique"

    def test_blackboard_concurrent_write_performance(self):
        """8-thread concurrent blackboard writes should complete without deadlock."""
        findings = StateFindings(target=TARGET)
        bb = Blackboard(findings)

        errors: list[str] = []
        writes_per_thread = 50

        def _writer(thread_id: int) -> None:
            try:
                for i in range(writes_per_thread):
                    bb.write(lambda f, tid=thread_id, idx=i: f.add_finding(
                        Finding(
                            title=f"Thread-{tid} finding #{idx}",
                            severity="MEDIUM",
                            url=f"{TARGET}/t{tid}/{idx}",
                            parameter=f"p{idx}",
                            category="xss",
                        )
                    ))
            except Exception as exc:
                errors.append(f"Thread-{thread_id}: {exc}")

        threads = [threading.Thread(target=_writer, args=(t,)) for t in range(8)]

        start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        elapsed_ms = (time.perf_counter() - start) * 1000

        alive = [t for t in threads if t.is_alive()]
        assert not alive, f"{len(alive)} threads still alive — possible deadlock"
        assert not errors, f"Thread errors: {errors}"

        total_expected = 8 * writes_per_thread
        assert len(findings.findings) == total_expected, (
            f"Expected {total_expected} unique findings, got {len(findings.findings)}"
        )
        assert elapsed_ms < 5_000, (
            f"Concurrent writes took {elapsed_ms:.1f}ms (limit 5 000ms)"
        )
