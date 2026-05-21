"""ChainPlanner: template matching, deduplication, and ranking."""
from __future__ import annotations

from autopnex.state_machine.attack_graph import AttackGraph
from autopnex.state_machine.chain_planner import ChainPlanner, IMPACT_ORDER
from autopnex.state_machine.findings import Finding, StateFindings


def _make_findings(entries):
    sf = StateFindings(target="http://t")
    for entry in entries:
        sf.add_finding(Finding(**entry))
    return sf


# ── SQLi template matching ───────────────────────────────────────────────


def test_sqli_template_match():
    sf = _make_findings([{
        "title": "SQL Injection in id",
        "severity": "HIGH",
        "status": "confirmed",
        "category": "sqli",
        "url": "http://t/item",
        "parameter": "id",
    }])
    graph = AttackGraph()
    planner = ChainPlanner()
    chains = planner.plan(sf, graph)

    assert len(chains) == 1
    assert "SQLi" in chains[0].name
    assert chains[0].max_impact == "CRITICAL"
    assert len(chains[0].edges) == 5
    assert len(graph.nodes) > 0
    assert len(graph.edges) == 5


# ── XSS template matching ───────────────────────────────────────────────


def test_xss_template_match():
    sf = _make_findings([{
        "title": "Reflected XSS in q",
        "severity": "HIGH",
        "status": "confirmed",
        "category": "xss",
        "url": "http://t/search",
        "parameter": "q",
    }])
    graph = AttackGraph()
    planner = ChainPlanner()
    chains = planner.plan(sf, graph)

    assert len(chains) == 1
    assert "XSS" in chains[0].name
    assert chains[0].max_impact == "HIGH"


# ── No chains for non-exploitable findings ───────────────────────────────


def test_no_chains_for_suspected_findings():
    sf = _make_findings([{
        "title": "Maybe SQLi",
        "severity": "MEDIUM",
        "status": "suspected",
        "category": "sqli",
        "url": "http://t/x",
        "parameter": "id",
    }])
    graph = AttackGraph()
    chains = ChainPlanner().plan(sf, graph)
    assert chains == []


def test_no_chains_for_unknown_category():
    sf = _make_findings([{
        "title": "Info disclosure",
        "severity": "LOW",
        "status": "confirmed",
        "category": "info",
    }])
    graph = AttackGraph()
    chains = ChainPlanner().plan(sf, graph)
    assert chains == []


# ── Deduplication ────────────────────────────────────────────────────────


def test_deduplication_of_same_template():
    sf = _make_findings([
        {
            "title": "SQLi #1",
            "severity": "HIGH",
            "status": "confirmed",
            "category": "sqli",
            "url": "http://t/a",
            "parameter": "id",
        },
        {
            "title": "SQLi #2",
            "severity": "HIGH",
            "status": "confirmed",
            "category": "sqli",
            "url": "http://t/b",
            "parameter": "q",
        },
    ])
    graph = AttackGraph()
    chains = ChainPlanner().plan(sf, graph)
    assert len(chains) == 1


# ── Ranking by impact ────────────────────────────────────────────────────


def test_ranking_by_impact():
    sf = _make_findings([
        {
            "title": "XSS in q",
            "severity": "HIGH",
            "status": "confirmed",
            "category": "xss",
            "url": "http://t/search",
            "parameter": "q",
        },
        {
            "title": "SQLi in id",
            "severity": "HIGH",
            "status": "confirmed",
            "category": "sqli",
            "url": "http://t/item",
            "parameter": "id",
        },
    ])
    graph = AttackGraph()
    chains = ChainPlanner().plan(sf, graph)

    assert len(chains) == 2
    assert chains[0].max_impact == "CRITICAL"
    assert chains[1].max_impact == "HIGH"


def test_impact_order_values():
    assert IMPACT_ORDER["LOW"] < IMPACT_ORDER["MEDIUM"]
    assert IMPACT_ORDER["MEDIUM"] < IMPACT_ORDER["HIGH"]
    assert IMPACT_ORDER["HIGH"] < IMPACT_ORDER["CRITICAL"]
