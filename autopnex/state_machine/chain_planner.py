"""Template-driven attack chain planner.

Matches confirmed findings against known multi-step exploitation templates
and builds concrete :class:`AttackChain` instances inside the attack graph.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .attack_graph import AttackGraph, AttackChain, NodeType
from .findings import StateFindings

IMPACT_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ---------------------------------------------------------------------------
# Chain templates
# ---------------------------------------------------------------------------
# Each template is keyed by the trigger finding category.  ``steps`` is an
# ordered list of (label, tool, risk_level, requires_approval) tuples that
# will be materialised into graph edges when the trigger finding is present.

CHAIN_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "name": "SQLi → Credential Dump → Admin Login → File Upload → RCE",
        "description": (
            "Leverage SQL injection to extract credentials, log in to the admin "
            "panel, upload a web shell via the file-upload endpoint, and achieve "
            "remote code execution."
        ),
        "mitre_tactics": [
            "TA0001-Initial Access",
            "TA0006-Credential Access",
            "TA0004-Privilege Escalation",
            "TA0002-Execution",
        ],
        "max_impact": "CRITICAL",
        "steps": [
            ("SQL Injection Exploit", "sqli_exploit", "high", False),
            ("Credential Dump", "sqli_exploit", "high", True),
            ("Admin Login", "auth_bypass", "medium", False),
            ("File Upload PoC", "file_upload_exploit", "high", True),
            ("Remote Code Execution", "finding_replay", "critical", True),
        ],
    },
    "xss": {
        "name": "XSS → Cookie Theft → Session Hijack → Privileged API Access",
        "description": (
            "Use reflected XSS to steal session cookies, hijack an "
            "authenticated session, then access privileged API endpoints."
        ),
        "mitre_tactics": [
            "TA0001-Initial Access",
            "TA0006-Credential Access",
            "TA0004-Privilege Escalation",
            "TA0009-Collection",
        ],
        "max_impact": "HIGH",
        "steps": [
            ("XSS Exploit", "xss_exploit", "medium", False),
            ("Cookie Theft", "xss_exploit", "medium", False),
            ("Session Hijack", "auth_bypass", "high", True),
            ("Privileged API Access", "privilege_escalation", "high", True),
        ],
    },
    "ssrf": {
        "name": "SSRF → Internal Service Discovery → Cloud Metadata → Credential Theft",
        "description": (
            "Abuse SSRF to probe internal services, reach the cloud metadata "
            "endpoint, and steal IAM / service-account credentials."
        ),
        "mitre_tactics": [
            "TA0001-Initial Access",
            "TA0007-Discovery",
            "TA0006-Credential Access",
            "TA0009-Collection",
        ],
        "max_impact": "CRITICAL",
        "steps": [
            ("SSRF Exploit", "finding_replay", "high", False),
            ("Internal Service Discovery", "finding_replay", "high", False),
            ("Cloud Metadata Access", "finding_replay", "critical", True),
            ("Credential Theft", "finding_replay", "critical", True),
        ],
    },
    "cmdi": {
        "name": "CMDi → Shell Access → Privilege Escalation → Persistence",
        "description": (
            "Exploit command injection to obtain a shell, escalate privileges "
            "to root/admin, and install persistence mechanisms."
        ),
        "mitre_tactics": [
            "TA0001-Initial Access",
            "TA0002-Execution",
            "TA0004-Privilege Escalation",
            "TA0003-Persistence",
        ],
        "max_impact": "CRITICAL",
        "steps": [
            ("Command Injection Exploit", "finding_replay", "critical", False),
            ("Shell Access", "finding_replay", "critical", True),
            ("Privilege Escalation", "privilege_escalation", "critical", True),
            ("Persistence Install", "finding_replay", "critical", True),
        ],
    },
}


class ChainPlanner:
    """Builds attack chains by matching findings against known templates."""

    def plan(self, findings: StateFindings, graph: AttackGraph) -> List[AttackChain]:
        """Main entry point — returns newly created chains."""
        raw = self._match_templates(findings, graph)
        return self._rank_and_deduplicate(raw)

    # ------------------------------------------------------------------
    def _match_templates(
        self,
        findings: StateFindings,
        graph: AttackGraph,
    ) -> List[AttackChain]:
        chains: List[AttackChain] = []
        for finding in findings.findings:
            template = CHAIN_TEMPLATES.get(finding.category)
            if template is None:
                continue
            if finding.status not in ("confirmed", "exploitable", "exploited"):
                continue

            trigger_node = graph.add_node(
                NodeType.VULNERABILITY,
                finding.title,
                finding_key=f"{finding.title}|{finding.url}|{finding.parameter}",
                metadata={"url": finding.url, "parameter": finding.parameter},
            )
            trigger_node.obtained_at = findings.started_at

            prev_id = trigger_node.node_id
            edge_ids: List[str] = []
            for label, tool, risk, approval in template["steps"]:
                step_node = graph.add_node(
                    NodeType.CAPABILITY,
                    label,
                    metadata={"tool": tool},
                )
                edge = graph.add_edge(
                    prev_id,
                    step_node.node_id,
                    tool,
                    preconditions=[prev_id],
                    risk_level=risk,
                    requires_approval=approval,
                )
                edge_ids.append(edge.edge_id)
                prev_id = step_node.node_id

            chain = graph.add_chain(
                template["name"],
                edge_ids,
                description=template["description"],
                mitre_tactics=template["mitre_tactics"],
                max_impact=template["max_impact"],
            )
            chains.append(chain)
        return chains

    # ------------------------------------------------------------------
    @staticmethod
    def _rank_and_deduplicate(chains: List[AttackChain]) -> List[AttackChain]:
        seen_names: set[str] = set()
        unique: List[AttackChain] = []
        for chain in chains:
            if chain.name in seen_names:
                continue
            seen_names.add(chain.name)
            unique.append(chain)
        unique.sort(
            key=lambda c: IMPACT_ORDER.get(c.max_impact, 0),
            reverse=True,
        )
        return unique
