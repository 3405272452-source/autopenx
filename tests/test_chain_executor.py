"""ChainExecutor: checkpoints, execution, failure, approval gates, preconditions."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from autopnex.state_machine.attack_graph import (
    AttackGraph,
    EdgeStatus,
    NodeType,
)
from autopnex.state_machine.chain_executor import ChainExecutor, Checkpoint
from autopnex.state_machine.findings import StateFindings
from autopnex.tools.base import ToolResult


def _build_graph_with_chain():
    """Helper: graph with 3-step chain, all preconditions trivially met."""
    g = AttackGraph()
    root = g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="root")
    root.obtained_at = "2025-01-01T00:00:00Z"

    s1 = g.add_node(NodeType.CAPABILITY, "Step1", node_id="s1")
    s2 = g.add_node(NodeType.CAPABILITY, "Step2", node_id="s2")
    s3 = g.add_node(NodeType.CAPABILITY, "Step3", node_id="s3")

    g.add_edge("root", "s1", "tool_a", edge_id="e1", preconditions=["root"])
    g.add_edge("s1", "s2", "tool_b", edge_id="e2", preconditions=["s1"])
    g.add_edge("s2", "s3", "tool_c", edge_id="e3", preconditions=["s2"])

    g.add_chain("Test Chain", ["e1", "e2", "e3"], chain_id="c1")
    return g


# ── Checkpoint creation ──────────────────────────────────────────────────


def test_checkpoint_created_per_step():
    g = _build_graph_with_chain()
    sf = StateFindings(target="http://t")

    with patch("autopnex.state_machine.chain_executor.ToolRegistry") as mock_reg:
        mock_reg.execute.return_value = ToolResult(
            success=True, tool="tool_a", summary="ok"
        )
        executor = ChainExecutor(g, sf)
        result = executor.execute_chain("c1")

    assert result["status"] == "completed"
    assert len(executor.checkpoints) == 3
    assert all(isinstance(cp, Checkpoint) for cp in executor.checkpoints)
    assert executor.checkpoints[0].step_idx == 0
    assert executor.checkpoints[1].step_idx == 1


def test_checkpoint_contains_graph_snapshot():
    g = _build_graph_with_chain()
    sf = StateFindings(target="http://t")

    with patch("autopnex.state_machine.chain_executor.ToolRegistry") as mock_reg:
        mock_reg.execute.return_value = ToolResult(
            success=True, tool="tool_a", summary="ok"
        )
        executor = ChainExecutor(g, sf)
        executor.execute_chain("c1")

    cp = executor.checkpoints[0]
    assert "nodes" in cp.graph_snapshot
    assert "edges" in cp.graph_snapshot
    assert cp.to_dict()["chain_id"] == "c1"


# ── Successful chain execution ───────────────────────────────────────────


def test_successful_chain_execution():
    g = _build_graph_with_chain()
    sf = StateFindings(target="http://t")

    with patch("autopnex.state_machine.chain_executor.ToolRegistry") as mock_reg:
        mock_reg.execute.return_value = ToolResult(
            success=True, tool="tool_a", summary="exploited"
        )
        executor = ChainExecutor(g, sf)
        result = executor.execute_chain("c1")

    assert result["status"] == "completed"
    assert len(result["steps"]) == 3
    assert all(s["success"] for s in result["steps"])

    for eid in ("e1", "e2", "e3"):
        assert g.edges[eid].status == EdgeStatus.EXECUTED


# ── Failed step stops chain ──────────────────────────────────────────────


def test_failed_step_stops_chain():
    g = _build_graph_with_chain()
    sf = StateFindings(target="http://t")

    call_count = 0

    def _side_effect(tool, args, *a, **kw):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return ToolResult(success=True, tool=tool, summary="ok")
        return ToolResult(success=False, tool=tool, summary="fail", error="err")

    with patch("autopnex.state_machine.chain_executor.ToolRegistry") as mock_reg:
        mock_reg.execute.side_effect = _side_effect
        executor = ChainExecutor(g, sf)
        result = executor.execute_chain("c1")

    assert result["status"] == "failed"
    assert g.edges["e1"].status == EdgeStatus.EXECUTED
    assert g.edges["e2"].status == EdgeStatus.EXECUTED
    assert g.edges["e3"].status == EdgeStatus.FAILED


# ── Approval gate blocks execution ───────────────────────────────────────


def test_approval_gate_blocks_execution():
    g = AttackGraph()
    root = g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="root")
    root.obtained_at = "2025-01-01T00:00:00Z"
    g.add_node(NodeType.CAPABILITY, "Step1", node_id="s1")
    g.add_edge(
        "root", "s1", "tool_a",
        edge_id="e1",
        preconditions=["root"],
        requires_approval=True,
    )
    g.add_chain("Blocked Chain", ["e1"], chain_id="c1")

    sf = StateFindings(target="http://t")
    executor = ChainExecutor(g, sf, approval_cb=lambda edge: False)
    result = executor.execute_chain("c1")

    assert result["status"] == "blocked"
    assert g.edges["e1"].status == EdgeStatus.BLOCKED


def test_approval_auto_approved_when_no_callback():
    g = AttackGraph()
    root = g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="root")
    root.obtained_at = "2025-01-01T00:00:00Z"
    g.add_node(NodeType.CAPABILITY, "Step1", node_id="s1")
    g.add_edge(
        "root", "s1", "tool_a",
        edge_id="e1",
        preconditions=["root"],
        requires_approval=True,
    )
    g.add_chain("Auto Chain", ["e1"], chain_id="c1")

    sf = StateFindings(target="http://t")

    with patch("autopnex.state_machine.chain_executor.ToolRegistry") as mock_reg:
        mock_reg.execute.return_value = ToolResult(
            success=True, tool="tool_a", summary="ok"
        )
        executor = ChainExecutor(g, sf, approval_cb=None)
        result = executor.execute_chain("c1")

    assert result["status"] == "completed"


# ── Preconditions check ─────────────────────────────────────────────────


def test_preconditions_unmet_blocks_chain():
    g = AttackGraph()
    g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="root")
    g.add_node(NodeType.CAPABILITY, "Step1", node_id="s1")
    g.add_edge("root", "s1", "tool_a", edge_id="e1", preconditions=["root"])
    g.add_chain("Blocked Pre", ["e1"], chain_id="c1")

    sf = StateFindings(target="http://t")
    executor = ChainExecutor(g, sf)
    result = executor.execute_chain("c1")

    assert result["status"] == "blocked"
    assert result["steps"][0]["status"] == "preconditions_unmet"


# ── Unknown chain ID ────────────────────────────────────────────────────


def test_unknown_chain_returns_error():
    g = AttackGraph()
    sf = StateFindings(target="http://t")
    executor = ChainExecutor(g, sf)
    result = executor.execute_chain("nonexistent")

    assert result["success"] is False
    assert "not found" in result["error"]


# ── Progress callback ───────────────────────────────────────────────────


def test_progress_callback_called():
    g = _build_graph_with_chain()
    sf = StateFindings(target="http://t")
    progress_events = []

    with patch("autopnex.state_machine.chain_executor.ToolRegistry") as mock_reg:
        mock_reg.execute.return_value = ToolResult(
            success=True, tool="tool_a", summary="ok"
        )
        executor = ChainExecutor(
            g, sf,
            progress_cb=lambda *args: progress_events.append(args),
        )
        executor.execute_chain("c1")

    assert len(progress_events) >= 4
