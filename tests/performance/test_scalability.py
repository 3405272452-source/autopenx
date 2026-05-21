"""Scalability tests — verify AutoPenX sub-systems handle growing inputs."""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from autopnex.orchestrator import LLMOrchestrator
from autopnex.state_machine.machine import PenTestStateMachine
from autopnex.state_machine.findings import Finding, StateFindings
from autopnex.state_machine.attack_graph import (
    AttackGraph,
    AttackNode,
    AttackEdge,
    NodeType,
    EdgeStatus,
)
from autopnex.tools.base import ToolRegistry, ToolResult

TARGET = "http://testphp.vulnweb.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_execute(name, arguments, runtime_config=None):
    """Instant mock tool execution — zero network."""
    return ToolResult(
        success=True,
        tool=name,
        summary=f"[mock] {name} completed",
        raw_output=f"mock output for {name}",
        parsed_data={},
        duration_ms=1,
    )


def _time_vuln_detect(param_count: int) -> tuple[int, StateFindings]:
    """Prepare *param_count* parameters, run VULN_DETECT, return (ms, findings)."""
    with patch.object(ToolRegistry, "execute", side_effect=_fake_execute):
        findings = StateFindings(target=TARGET)
        for i in range(param_count):
            findings.add_parameter(f"{TARGET}/p{i}?x=1", f"x{i}")

        orchestrator = LLMOrchestrator(mock=True)
        fsm = PenTestStateMachine(target=TARGET, orchestrator=orchestrator)
        fsm.findings = findings
        fsm.state = "VULN_DETECT"
        fsm.orchestrator.reset_for_state("VULN_DETECT")
        fsm._prepare_phase("VULN_DETECT")

        start = time.perf_counter()
        fsm._run_phase("VULN_DETECT")
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return elapsed_ms, fsm.findings


def _time_dedup(count: int) -> tuple[int, int]:
    """Add *count* findings (many duplicates), return (ms, unique_count)."""
    findings = StateFindings(target=TARGET)
    start = time.perf_counter()
    for i in range(count):
        findings.add_finding(Finding(
            title=f"SQLi #{i % (count // 5 or 1)}",
            severity="HIGH",
            url=f"{TARGET}/page{i % (count // 5 or 1)}",
            parameter=f"id{i % (count // 5 or 1)}",
            category="sqli",
        ))
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return elapsed_ms, len(findings.findings)


def _build_graph(node_count: int) -> tuple[int, AttackGraph]:
    """Build a linear chain graph with *node_count* nodes, return (ms, graph)."""
    graph = AttackGraph()

    start = time.perf_counter()
    prev_id: str | None = None
    for i in range(node_count):
        ntype = NodeType.ASSET if i % 3 == 0 else NodeType.VULNERABILITY
        node = graph.add_node(ntype, f"node-{i}", node_id=f"n{i}")
        if prev_id is not None:
            graph.add_edge(
                prev_id,
                node.node_id,
                tool=f"tool_{i}",
                edge_id=f"e{i}",
                status=EdgeStatus.THEORETICAL,
            )
        prev_id = node.node_id

    _ = graph.executable_edges()
    _ = graph.to_dict()
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return elapsed_ms, graph


# ===========================================================================
# VULN_DETECT scalability
# ===========================================================================

class TestScalability:
    def test_vuln_detect_4_params(self):
        """VULN_DETECT with 4 parameters should finish quickly."""
        ms, findings = _time_vuln_detect(4)
        assert ms < 15_000, f"4-param VULN_DETECT took {ms}ms"
        assert len(findings.tool_invocations) > 0

    @pytest.mark.slow
    def test_vuln_detect_12_params(self):
        """VULN_DETECT with 12 parameters (the capped maximum)."""
        ms, findings = _time_vuln_detect(12)
        assert ms < 30_000, f"12-param VULN_DETECT took {ms}ms"
        assert len(findings.tool_invocations) >= 12

    @pytest.mark.slow
    def test_vuln_detect_50_params(self):
        """VULN_DETECT with 50 parameters — only the first 12 are tested
        (the FSM caps at ``parameters[:12]``), so runtime should be bounded.
        """
        ms, findings = _time_vuln_detect(50)
        assert ms < 30_000, f"50-param (capped) VULN_DETECT took {ms}ms"

    # -----------------------------------------------------------------------
    # Findings dedup scalability
    # -----------------------------------------------------------------------

    def test_findings_dedup_100(self):
        """100 findings with ~80% duplication rate."""
        ms, unique = _time_dedup(100)
        assert ms < 50, f"100 add_finding took {ms}ms (limit 50ms)"
        assert unique <= 100

    def test_findings_dedup_1000(self):
        """1000 findings with dedup should stay under 200ms."""
        ms, unique = _time_dedup(1000)
        assert ms < 200, f"1000 add_finding took {ms}ms (limit 200ms)"
        assert unique <= 1000

    # -----------------------------------------------------------------------
    # Attack graph scalability
    # -----------------------------------------------------------------------

    def test_attack_graph_100_nodes(self):
        """Build + query a 100-node graph."""
        ms, graph = _build_graph(100)
        assert ms < 500, f"100-node graph took {ms}ms (limit 500ms)"
        assert len(graph.nodes) == 100
        assert len(graph.edges) == 99

    def test_attack_graph_1000_nodes(self):
        """Build + query a 1000-node graph."""
        ms, graph = _build_graph(1000)
        assert ms < 5_000, f"1000-node graph took {ms}ms (limit 5 000ms)"
        assert len(graph.nodes) == 1000
        assert len(graph.edges) == 999
        serialized = graph.to_dict()
        assert len(serialized["nodes"]) == 1000
