"""AttackGraph, AttackNode, AttackEdge — creation, traversal, serialization."""
from __future__ import annotations

from autopnex.state_machine.attack_graph import (
    AttackGraph,
    AttackNode,
    AttackEdge,
    AttackChain,
    EdgeStatus,
    NodeType,
)


# ── Node creation and serialization ──────────────────────────────────────


def test_attack_node_creation():
    node = AttackNode(
        node_id="n1",
        node_type=NodeType.VULNERABILITY,
        label="SQLi",
        finding_key="SQLi|http://t/x|id",
    )
    assert node.node_id == "n1"
    assert node.node_type == NodeType.VULNERABILITY
    assert node.label == "SQLi"
    assert node.obtained_at is None


def test_node_type_enum_values():
    assert NodeType.ASSET.value == "asset"
    assert NodeType.VULNERABILITY.value == "vulnerability"
    assert NodeType.CAPABILITY.value == "capability"


# ── Edge creation and preconditions ──────────────────────────────────────


def test_attack_edge_creation():
    edge = AttackEdge(
        edge_id="e1",
        source_id="n1",
        target_id="n2",
        tool="sqli_exploit",
        preconditions=["n0"],
        risk_level="high",
        requires_approval=True,
    )
    assert edge.edge_id == "e1"
    assert edge.status == EdgeStatus.THEORETICAL
    assert edge.preconditions == ["n0"]
    assert edge.requires_approval is True


def test_edge_status_enum_values():
    values = {s.value for s in EdgeStatus}
    assert values == {"theoretical", "validated", "executed", "failed", "blocked"}


# ── AttackGraph methods ──────────────────────────────────────────────────


def test_add_node_returns_node():
    g = AttackGraph()
    node = g.add_node(NodeType.ASSET, "Web Server", node_id="ws1")
    assert node.node_id == "ws1"
    assert "ws1" in g.nodes


def test_add_node_auto_generates_id():
    g = AttackGraph()
    node = g.add_node(NodeType.VULNERABILITY, "XSS")
    assert len(node.node_id) == 12
    assert node.node_id in g.nodes


def test_add_edge():
    g = AttackGraph()
    g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="n1")
    g.add_node(NodeType.CAPABILITY, "DB Dump", node_id="n2")
    edge = g.add_edge("n1", "n2", "sqli_exploit", edge_id="e1")
    assert edge.edge_id == "e1"
    assert "e1" in g.edges


def test_add_chain():
    g = AttackGraph()
    g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="n1")
    g.add_node(NodeType.CAPABILITY, "Shell", node_id="n2")
    e = g.add_edge("n1", "n2", "sqli_exploit", edge_id="e1")
    chain = g.add_chain("SQLi Chain", ["e1"], chain_id="c1", max_impact="CRITICAL")
    assert chain.chain_id == "c1"
    assert chain.edges == ["e1"]
    assert "c1" in g.chains


# ── Traversal ────────────────────────────────────────────────────────────


def test_reachable_from():
    g = AttackGraph()
    g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="n1")
    g.add_node(NodeType.CAPABILITY, "Dump", node_id="n2")
    g.add_node(NodeType.CAPABILITY, "Shell", node_id="n3")
    g.add_edge("n1", "n2", "sqli_exploit", edge_id="e1")
    g.add_edge("n1", "n3", "cmdi", edge_id="e2")
    g.add_edge("n2", "n3", "privesc", edge_id="e3")

    reachable = g.reachable_from("n1")
    assert len(reachable) == 2
    edge_ids = {e.edge_id for e in reachable}
    assert edge_ids == {"e1", "e2"}


def test_reachable_from_leaf_returns_empty():
    g = AttackGraph()
    g.add_node(NodeType.CAPABILITY, "End", node_id="leaf")
    assert g.reachable_from("leaf") == []


# ── Preconditions ────────────────────────────────────────────────────────


def test_preconditions_met_with_obtained():
    g = AttackGraph()
    n1 = g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="n1")
    n1.obtained_at = "2025-01-01T00:00:00Z"
    g.add_node(NodeType.CAPABILITY, "Dump", node_id="n2")
    edge = g.add_edge("n1", "n2", "sqli_exploit", preconditions=["n1"])

    assert g.preconditions_met(edge) is True


def test_preconditions_not_met():
    g = AttackGraph()
    g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="n1")
    g.add_node(NodeType.CAPABILITY, "Dump", node_id="n2")
    edge = g.add_edge("n1", "n2", "sqli_exploit", preconditions=["n1"])

    assert g.preconditions_met(edge) is False


def test_preconditions_empty_always_met():
    g = AttackGraph()
    g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="n1")
    g.add_node(NodeType.CAPABILITY, "Dump", node_id="n2")
    edge = g.add_edge("n1", "n2", "sqli_exploit", preconditions=[])
    assert g.preconditions_met(edge) is True


# ── Executable edges ─────────────────────────────────────────────────────


def test_executable_edges_filtering():
    g = AttackGraph()
    root = g.add_node(NodeType.ASSET, "Root", node_id="root")
    root.obtained_at = "2025-01-01T00:00:00Z"
    g.add_node(NodeType.CAPABILITY, "Step1", node_id="s1")
    g.add_node(NodeType.CAPABILITY, "Step2", node_id="s2")

    e1 = g.add_edge("root", "s1", "tool_a", preconditions=["root"], edge_id="e1")
    e2 = g.add_edge("s1", "s2", "tool_b", preconditions=["s1"], edge_id="e2")

    executable = g.executable_edges()
    assert len(executable) == 1
    assert executable[0].edge_id == "e1"


def test_executable_excludes_executed_edges():
    g = AttackGraph()
    root = g.add_node(NodeType.ASSET, "Root", node_id="root")
    root.obtained_at = "2025-01-01T00:00:00Z"
    g.add_node(NodeType.CAPABILITY, "Step1", node_id="s1")
    edge = g.add_edge("root", "s1", "tool_a", preconditions=["root"])
    edge.status = EdgeStatus.EXECUTED

    assert g.executable_edges() == []


# ── Obtained assets ──────────────────────────────────────────────────────


def test_obtained_assets():
    g = AttackGraph()
    n1 = g.add_node(NodeType.ASSET, "A", node_id="n1")
    n2 = g.add_node(NodeType.ASSET, "B", node_id="n2")
    g.add_node(NodeType.ASSET, "C", node_id="n3")

    n1.obtained_at = "2025-01-01T00:00:00Z"
    n2.obtained_at = "2025-01-01T00:00:00Z"

    assert g.obtained_assets() == {"n1", "n2"}


# ── Serialization ────────────────────────────────────────────────────────


def test_to_dict_serialization():
    g = AttackGraph()
    g.add_node(NodeType.VULNERABILITY, "SQLi", node_id="n1")
    g.add_node(NodeType.CAPABILITY, "Shell", node_id="n2")
    g.add_edge("n1", "n2", "sqli_exploit", edge_id="e1")
    g.add_chain("Chain A", ["e1"], chain_id="c1")

    d = g.to_dict()
    assert "nodes" in d and "edges" in d and "chains" in d
    assert "n1" in d["nodes"]
    assert d["nodes"]["n1"]["label"] == "SQLi"
    assert "e1" in d["edges"]
    assert d["edges"]["e1"]["tool"] == "sqli_exploit"
    assert "c1" in d["chains"]
    assert d["chains"]["c1"]["edges"] == ["e1"]


def test_to_dict_empty_graph():
    g = AttackGraph()
    d = g.to_dict()
    assert d == {"nodes": {}, "edges": {}, "chains": {}}
