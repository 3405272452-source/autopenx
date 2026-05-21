"""Benchmark metrics collection and reporting.

Compares AutoPenX scan results against ground-truth expected vulnerabilities
to compute detection recall, precision, F1, coverage, and performance stats.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from autopnex.state_machine.findings import StateFindings


@dataclass
class BenchmarkResult:
    target: str
    timestamp: str
    mode: str  # "single_agent" | "multi_agent"

    # Recon metrics
    ports_discovered: int = 0
    ports_expected: int = 0
    techs_discovered: int = 0
    techs_expected: int = 0
    recon_coverage: float = 0.0

    # Scan metrics
    paths_discovered: int = 0
    paths_expected: int = 0
    params_discovered: int = 0
    params_expected: int = 0
    scan_coverage: float = 0.0

    # Detection metrics
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    detection_recall: float = 0.0
    detection_precision: float = 0.0
    detection_f1: float = 0.0

    # Exploitation metrics
    exploit_attempts: int = 0
    exploit_successes: int = 0
    exploit_rate: float = 0.0

    # Attack chain metrics
    chains_planned: int = 0
    chains_executed: int = 0
    chains_completed: int = 0

    # Performance metrics
    total_duration_ms: int = 0
    llm_calls: int = 0
    tool_invocations: int = 0
    api_tokens_used: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        """Write result to a JSON file, merging into an existing array."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        existing: List[Dict[str, Any]] = []
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = [existing]
            except (json.JSONDecodeError, OSError):
                existing = []
        existing.append(self.to_dict())
        path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")

    def summary(self) -> str:
        """Pretty ASCII table of the benchmark result."""
        w = 60
        lines = [
            "",
            "=" * w,
            f"  AUTOPENX BENCHMARK — {self.target.upper()}",
            f"  Mode: {self.mode}  |  {self.timestamp}",
            "=" * w,
            "",
            "  RECON COVERAGE",
            f"    Ports:  {self.ports_discovered}/{self.ports_expected}",
            f"    Techs:  {self.techs_discovered}/{self.techs_expected}",
            f"    Score:  {self.recon_coverage:.1%}",
            "",
            "  SCAN COVERAGE",
            f"    Paths:  {self.paths_discovered}/{self.paths_expected}",
            f"    Params: {self.params_discovered}/{self.params_expected}",
            f"    Score:  {self.scan_coverage:.1%}",
            "",
            "  DETECTION",
            f"    TP: {self.true_positives}  FP: {self.false_positives}  FN: {self.false_negatives}",
            f"    Recall:    {self.detection_recall:.1%}",
            f"    Precision: {self.detection_precision:.1%}",
            f"    F1 Score:  {self.detection_f1:.1%}",
            "",
            "  EXPLOITATION",
            f"    Attempts:  {self.exploit_attempts}",
            f"    Successes: {self.exploit_successes}",
            f"    Rate:      {self.exploit_rate:.1%}",
            "",
            "  ATTACK CHAINS",
            f"    Planned:   {self.chains_planned}",
            f"    Executed:  {self.chains_executed}",
            f"    Completed: {self.chains_completed}",
            "",
            "  PERFORMANCE",
            f"    Duration:     {self.total_duration_ms:,} ms",
            f"    LLM Calls:    {self.llm_calls}",
            f"    Tool Calls:   {self.tool_invocations}",
            f"    API Tokens:   {self.api_tokens_used:,}",
            "",
            "=" * w,
        ]
        return "\n".join(lines)


# ---- Type normalisation helpers ----------------------------------------

_TYPE_ALIASES: Dict[str, str] = {
    "xss_reflected": "xss",
    "xss_stored": "xss",
    "xss_dom": "xss",
    "cmdi": "cmdi",
    "command_injection": "cmdi",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "ssrf": "ssrf",
    "lfi": "lfi",
    "file_inclusion": "lfi",
    "rfi": "rfi",
    "idor": "idor",
    "csrf": "csrf",
    "file_upload": "file_upload",
    "brute_force": "brute_force",
    "auth_bypass": "auth_bypass",
    "xxe": "xxe",
    "path_traversal": "path_traversal",
    "insecure_deserialization": "insecure_deserialization",
    "jwt_bypass": "jwt_bypass",
    "sensitive_exposure": "sensitive_exposure",
}


def _normalise_type(raw: str) -> str:
    return _TYPE_ALIASES.get(raw.lower().strip(), raw.lower().strip())


# ---- Main collector ----------------------------------------------------

class MetricsCollector:
    """Collects metrics by comparing scan findings against expected vulns."""

    def __init__(
        self,
        target: str,
        expected: Dict[str, Any],
        mode: str = "single_agent",
    ) -> None:
        self.target = target
        self.mode = mode
        self.expected = expected
        self._findings: Optional[StateFindings] = None
        self._start_time = datetime.now(timezone.utc)

    def record_findings(self, findings: StateFindings) -> None:
        self._findings = findings

    def compute(self) -> BenchmarkResult:
        """Compare findings against expected data and return a BenchmarkResult."""
        ts = datetime.now(timezone.utc).isoformat()
        result = BenchmarkResult(target=self.target, timestamp=ts, mode=self.mode)

        if self._findings is None:
            return result

        f = self._findings
        exp = self.expected

        # ---- Recon ----
        discovered_ports = {p.get("port") for p in f.open_ports if isinstance(p, dict)}
        expected_ports = set(exp.get("expected_ports", []))
        result.ports_discovered = len(discovered_ports & expected_ports)
        result.ports_expected = len(expected_ports)

        discovered_techs = {t.lower() for t in f.technologies}
        expected_techs = {t.lower() for t in exp.get("expected_techs", [])}
        result.techs_discovered = len(discovered_techs & expected_techs)
        result.techs_expected = len(expected_techs)

        recon_hits = result.ports_discovered + result.techs_discovered
        recon_total = result.ports_expected + result.techs_expected
        result.recon_coverage = recon_hits / recon_total if recon_total else 0.0

        # ---- Scan ----
        discovered_paths = set(f.discovered_paths)
        expected_paths = set(exp.get("expected_paths", []))
        result.paths_discovered = len(discovered_paths & expected_paths)
        result.paths_expected = len(expected_paths)

        expected_params = {
            (v["path"], v["parameter"])
            for v in exp.get("vulns", [])
            if v.get("parameter")
        }
        actual_params = set()
        for p in f.parameters:
            url = p.get("url", "")
            name = p.get("name", "")
            for path, param in expected_params:
                if path in url and name == param:
                    actual_params.add((path, param))
        result.params_discovered = len(actual_params)
        result.params_expected = len(expected_params)

        scan_hits = result.paths_discovered + result.params_discovered
        scan_total = result.paths_expected + result.params_expected
        result.scan_coverage = scan_hits / scan_total if scan_total else 0.0

        # ---- Detection (vuln matching) ----
        expected_vulns = exp.get("vulns", [])
        matched_expected: set[int] = set()
        matched_findings: set[int] = set()

        for fi, finding in enumerate(f.findings):
            ftype = _normalise_type(finding.category)
            found_match = False
            for ei, ev in enumerate(expected_vulns):
                if ei in matched_expected:
                    continue
                etype = _normalise_type(ev["type"])
                if ftype != etype:
                    continue
                path_match = (
                    not ev.get("path")
                    or ev["path"] in (finding.url or "")
                )
                param_match = (
                    not ev.get("parameter")
                    or ev["parameter"] == finding.parameter
                )
                if path_match and param_match:
                    matched_expected.add(ei)
                    matched_findings.add(fi)
                    found_match = True
                    break
            if not found_match:
                pass  # will be counted as FP

        result.true_positives = len(matched_expected)
        result.false_positives = len(f.findings) - len(matched_findings)
        result.false_negatives = len(expected_vulns) - len(matched_expected)

        tp, fp, fn = result.true_positives, result.false_positives, result.false_negatives
        result.detection_recall = tp / (tp + fn) if (tp + fn) else 0.0
        result.detection_precision = tp / (tp + fp) if (tp + fp) else 0.0
        if result.detection_recall + result.detection_precision > 0:
            result.detection_f1 = (
                2 * result.detection_recall * result.detection_precision
                / (result.detection_recall + result.detection_precision)
            )
        else:
            result.detection_f1 = 0.0

        # ---- Exploitation ----
        exploited = [e for e in f.findings if e.status == "exploited"]
        exploit_invocations = [
            inv for inv in f.tool_invocations
            if inv.state == "EXPLOIT"
        ]
        result.exploit_attempts = len(exploit_invocations)
        result.exploit_successes = len(exploited)
        result.exploit_rate = (
            result.exploit_successes / result.exploit_attempts
            if result.exploit_attempts else 0.0
        )

        # ---- Attack chains ----
        graph = f.attack_graph
        if graph is not None:
            chains = list(graph.chains.values())
            result.chains_planned = len(chains)
            result.chains_executed = sum(
                1 for c in chains if c.status in ("executing", "completed")
            )
            result.chains_completed = sum(
                1 for c in chains if c.status == "completed"
            )

        # ---- Performance ----
        total_ms = sum(inv.duration_ms for inv in f.tool_invocations)
        result.total_duration_ms = total_ms
        result.tool_invocations = len(f.tool_invocations)

        llm_calls = sum(
            1 for inv in f.tool_invocations
            if inv.tool not in ("port_scan", "tech_detect", "subdomain_find")
        )
        result.llm_calls = llm_calls
        result.api_tokens_used = 0

        return result
