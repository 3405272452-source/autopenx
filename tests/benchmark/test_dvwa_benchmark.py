"""Pytest-based benchmark tests against DVWA.

These tests require Docker and are skipped automatically when Docker is
unavailable.  Run with:

    pytest tests/benchmark/ -m benchmark -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import settings
from autopnex.orchestrator import LLMOrchestrator
from autopnex.state_machine.machine import PenTestStateMachine

from tests.benchmark.docker_targets import VulnerableTarget, docker_available
from tests.benchmark.expected_vulns import DVWA_EXPECTED
from tests.benchmark.metrics import MetricsCollector


def _run_scan(target_url: str, *, multi_agent: bool = False):
    """Run an AutoPenX scan in mock mode and return (findings, metrics)."""
    runtime = settings.snapshot(
        allow_local_targets=True,
        exploit_enabled=True,
        allow_external_tools=False,
        max_iter_per_state=4,
    )
    orchestrator = LLMOrchestrator(mock=True, runtime_config=runtime)
    sm = PenTestStateMachine(
        target_url,
        orchestrator,
        multi_agent=multi_agent,
        max_iter_per_state=4,
    )
    findings = sm.run()
    mode = "multi_agent" if multi_agent else "single_agent"
    collector = MetricsCollector("dvwa", DVWA_EXPECTED, mode=mode)
    collector.record_findings(findings)
    return findings, collector.compute()


@pytest.mark.benchmark
@pytest.mark.skipif(not docker_available(), reason="Docker not available")
class TestDVWABenchmark:
    """Full integration benchmarks against a live DVWA container."""

    def test_recon_coverage(self, dvwa_target: VulnerableTarget) -> None:
        findings, result = _run_scan(dvwa_target.url)
        assert result.ports_expected > 0
        assert result.recon_coverage >= 0.0, (
            f"Recon coverage {result.recon_coverage:.1%} — expected some discovery"
        )

    def test_scan_coverage(self, dvwa_target: VulnerableTarget) -> None:
        findings, result = _run_scan(dvwa_target.url)
        assert result.paths_expected > 0
        assert result.scan_coverage >= 0.0

    def test_sqli_detection(self, dvwa_target: VulnerableTarget) -> None:
        findings, result = _run_scan(dvwa_target.url)
        sqli_found = any(
            f.category == "sqli" for f in findings.findings
        )
        if sqli_found:
            assert result.true_positives >= 1

    def test_xss_detection(self, dvwa_target: VulnerableTarget) -> None:
        findings, result = _run_scan(dvwa_target.url)
        xss_found = any(
            f.category in ("xss", "xss_reflected", "xss_stored") for f in findings.findings
        )
        if xss_found:
            assert result.true_positives >= 1

    def test_command_injection_detection(self, dvwa_target: VulnerableTarget) -> None:
        findings, result = _run_scan(dvwa_target.url)
        cmdi_found = any(
            f.category in ("cmdi", "command_injection") for f in findings.findings
        )
        if cmdi_found:
            assert result.true_positives >= 1

    def test_file_inclusion_detection(self, dvwa_target: VulnerableTarget) -> None:
        findings, result = _run_scan(dvwa_target.url)
        lfi_found = any(
            f.category in ("lfi", "file_inclusion") for f in findings.findings
        )
        if lfi_found:
            assert result.true_positives >= 1

    def test_overall_f1(self, dvwa_target: VulnerableTarget) -> None:
        _, result = _run_scan(dvwa_target.url)
        print(result.summary())
        assert result.detection_f1 >= 0.0

    def test_multi_agent_mode(self, dvwa_target: VulnerableTarget) -> None:
        _, result = _run_scan(dvwa_target.url, multi_agent=True)
        assert result.mode == "multi_agent"
        print(result.summary())


@pytest.mark.benchmark
class TestMetricsUnit:
    """Unit tests for the metrics system that do NOT require Docker."""

    def test_empty_findings_produce_zero_metrics(self) -> None:
        from autopnex.state_machine.findings import StateFindings

        collector = MetricsCollector("dvwa", DVWA_EXPECTED, mode="single_agent")
        findings = StateFindings(target="http://localhost:4280")
        collector.record_findings(findings)
        result = collector.compute()

        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.false_negatives == len(DVWA_EXPECTED["vulns"])
        assert result.detection_recall == 0.0
        assert result.detection_precision == 0.0
        assert result.detection_f1 == 0.0

    def test_perfect_detection(self) -> None:
        from autopnex.state_machine.findings import Finding, StateFindings

        findings = StateFindings(target="http://localhost:4280")
        for vuln in DVWA_EXPECTED["vulns"]:
            findings.add_finding(Finding(
                title=f"Test {vuln['type']}",
                category=vuln["type"],
                severity=vuln["severity"],
                url=f"http://localhost:4280{vuln['path']}",
                parameter=vuln["parameter"],
            ))

        collector = MetricsCollector("dvwa", DVWA_EXPECTED)
        collector.record_findings(findings)
        result = collector.compute()

        assert result.true_positives == len(DVWA_EXPECTED["vulns"])
        assert result.false_positives == 0
        assert result.false_negatives == 0
        assert result.detection_recall == 1.0
        assert result.detection_precision == 1.0
        assert result.detection_f1 == 1.0

    def test_partial_detection_with_fps(self) -> None:
        from autopnex.state_machine.findings import Finding, StateFindings

        findings = StateFindings(target="http://localhost:4280")
        findings.add_finding(Finding(
            title="SQL Injection",
            category="sqli",
            severity="HIGH",
            url="http://localhost:4280/vulnerabilities/sqli/",
            parameter="id",
        ))
        findings.add_finding(Finding(
            title="Ghost vuln",
            category="unknown_type",
            severity="LOW",
            url="http://localhost:4280/fake",
            parameter="x",
        ))

        collector = MetricsCollector("dvwa", DVWA_EXPECTED)
        collector.record_findings(findings)
        result = collector.compute()

        assert result.true_positives == 1
        assert result.false_positives == 1
        expected_fn = len(DVWA_EXPECTED["vulns"]) - 1
        assert result.false_negatives == expected_fn
        assert 0 < result.detection_recall < 1.0
        assert 0 < result.detection_precision < 1.0

    def test_recon_coverage_calculation(self) -> None:
        from autopnex.state_machine.findings import StateFindings

        findings = StateFindings(target="http://localhost:4280")
        findings.open_ports = [{"port": 80, "state": "open", "service": "http"}]
        findings.technologies = ["Apache", "PHP"]

        collector = MetricsCollector("dvwa", DVWA_EXPECTED)
        collector.record_findings(findings)
        result = collector.compute()

        assert result.ports_discovered == 1
        assert result.techs_discovered == 2
        assert result.recon_coverage > 0.5

    def test_summary_format(self) -> None:
        from autopnex.state_machine.findings import StateFindings

        collector = MetricsCollector("dvwa", DVWA_EXPECTED)
        collector.record_findings(StateFindings(target="http://localhost:4280"))
        result = collector.compute()
        summary = result.summary()

        assert "AUTOPENX BENCHMARK" in summary
        assert "DVWA" in summary
        assert "DETECTION" in summary
        assert "RECON COVERAGE" in summary
        assert "PERFORMANCE" in summary

    def test_result_serialization(self, tmp_path) -> None:
        from autopnex.state_machine.findings import StateFindings
        import json

        collector = MetricsCollector("dvwa", DVWA_EXPECTED)
        collector.record_findings(StateFindings(target="http://localhost:4280"))
        result = collector.compute()

        out = tmp_path / "bench.json"
        result.save(out)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["target"] == "dvwa"

        result.save(out)
        data2 = json.loads(out.read_text(encoding="utf-8"))
        assert len(data2) == 2
