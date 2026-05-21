"""Pytest fixtures for benchmark tests with Docker target lifecycle."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Generator

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.benchmark.docker_targets import (
    TARGETS,
    TargetManager,
    VulnerableTarget,
    docker_available,
)
from tests.benchmark.expected_vulns import get_expected
from tests.benchmark.metrics import MetricsCollector

log = logging.getLogger("autopnex.benchmark.fixtures")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "benchmark: benchmark tests against vulnerable Docker targets")
    config.addinivalue_line("markers", "strict_benchmark: strict web benchmark — real LLM, must find flag")
    config.addinivalue_line("markers", "requires_deepseek: marks tests requiring DeepSeek API availability")


# ---- Docker availability check -----------------------------------------

_docker_ok: bool | None = None


def _check_docker() -> bool:
    global _docker_ok
    if _docker_ok is None:
        _docker_ok = docker_available()
    return _docker_ok


# ---- Shared target manager (session-scoped) ----------------------------

@pytest.fixture(scope="session")
def target_manager() -> Generator[TargetManager, None, None]:
    manager = TargetManager()
    yield manager
    manager.stop_all()


# ---- Individual target fixtures ----------------------------------------

@pytest.fixture(scope="session")
def dvwa_target(target_manager: TargetManager) -> Generator[VulnerableTarget, None, None]:
    if not _check_docker():
        pytest.skip("Docker not available")
    target = target_manager.start_and_wait("dvwa", timeout=90)
    yield target
    target_manager.stop("dvwa")


@pytest.fixture(scope="session")
def juice_shop_target(target_manager: TargetManager) -> Generator[VulnerableTarget, None, None]:
    if not _check_docker():
        pytest.skip("Docker not available")
    target = target_manager.start_and_wait("juice-shop", timeout=120)
    yield target
    target_manager.stop("juice-shop")


@pytest.fixture(scope="session")
def webgoat_target(target_manager: TargetManager) -> Generator[VulnerableTarget, None, None]:
    if not _check_docker():
        pytest.skip("Docker not available")
    target = target_manager.start_and_wait("webgoat", timeout=120)
    yield target
    target_manager.stop("webgoat")


# ---- Expected vuln fixtures -------------------------------------------

@pytest.fixture()
def dvwa_expected() -> dict:
    return get_expected("dvwa")


@pytest.fixture()
def juice_shop_expected() -> dict:
    return get_expected("juice-shop")


@pytest.fixture()
def webgoat_expected() -> dict:
    return get_expected("webgoat")


# ---- Metrics collector factory ----------------------------------------

# ---- Lightweight benchmark target fixture (no Docker) -------------------

@pytest.fixture(scope="function")
def benchmark_target(request):
    """Start a specific challenge target, yield it, then stop it.

    Usage:
        def test_lfi(benchmark_target):
            target = benchmark_target("lfi_basic")
            assert target.url.startswith("http://")
    """
    from tests.benchmark.challenges import ChallengeTarget
    from tests.benchmark.web_targets.registry import get_target_class

    started: dict = {}

    def _start(target_id: str) -> ChallengeTarget:
        if target_id in started:
            return started[target_id]

        cls = get_target_class(target_id)
        if cls is None:
            raise ValueError(f"Unknown benchmark target: {target_id}")

        target = cls()
        target.start()
        started[target_id] = target
        return target

    yield _start

    for tid, target in started.items():
        try:
            target.stop()
        except Exception:
            pass
        try:
            target.cleanup()
        except Exception:
            pass


@pytest.fixture()
def metrics_factory():
    """Factory fixture that returns a fresh MetricsCollector."""
    def _make(target_name: str, mode: str = "single_agent") -> MetricsCollector:
        expected = get_expected(target_name)
        return MetricsCollector(target_name, expected, mode=mode)
    return _make


# ---- Benchmark report generation hook -----------------------------------

import json
import time


def pytest_sessionfinish(session: pytest.Session) -> None:
    """Generate benchmark report after all strict_benchmark tests complete.

    Reads results stored by test_web_benchmark._store_result() on
    session.config._benchmark_results and writes JSON + Markdown reports.
    """
    results = getattr(session.config, "_benchmark_results", {})
    if not results:
        return

    report_dir = Path(session.config.rootdir) / "benchmark_results"
    report_dir.mkdir(exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_id = f"benchmark_12_{timestamp}"

    total = len(results)
    passed = sum(1 for r in results.values() if r.get("success"))
    failed = total - passed

    # Failure classification
    failure_reasons = {}
    for r in results.values():
        if not r.get("success"):
            reason = (r.get("failure_reason") or "unknown").split(":")[0]
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

    summary = {
        "run_id": run_id,
        "model": "multi_agent_rule_based",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": total,
        "passed": passed,
        "failed": failed,
        "success_rate": round(passed / total, 4) if total > 0 else 0,
        "avg_rounds": round(
            sum(r.get("rounds", 0) for r in results.values()) / total, 1
        ) if total > 0 else 0,
        "avg_time_seconds": round(
            sum(r.get("time_seconds", 0) for r in results.values()) / total, 2
        ) if total > 0 else 0,
        "failure_classification": failure_reasons,
        "results": [
            {
                "target_id": r.get("target_id"),
                "success": r.get("success"),
                "flag": r.get("flag"),
                "rounds": r.get("rounds"),
                "time_seconds": r.get("time_seconds"),
                "winning_route": r.get("winning_route"),
                "attribution": r.get("attribution"),
                "failure_reason": r.get("failure_reason"),
                "repeat_ratio": r.get("repeat_ratio"),
            }
            for r in results.values()
        ],
    }

    # Write JSON report
    json_path = report_dir / f"{run_id}.json"
    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Write Markdown report
    md_lines = [
        "# Strict Web Benchmark Report",
        "",
        f"**Run ID**: `{run_id}`",
        f"**Model**: {summary['model']}",
        f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total Targets | {total} |",
        f"| Passed | {passed} |",
        f"| Failed | {failed} |",
        f"| Success Rate | {summary['success_rate']:.0%} |",
        f"| Avg Rounds | {summary['avg_rounds']} |",
        f"| Avg Time | {summary['avg_time_seconds']}s |",
        "",
        "## Failure Classification",
        "",
        "| Reason | Count |",
        "|---|---|",
    ]
    for reason, count in sorted(failure_reasons.items(), key=lambda x: -x[1]):
        md_lines.append(f"| {reason} | {count} |")

    md_lines.extend([
        "",
        "## Per-Target Results",
        "",
        "| Target | Success | Flag | Rounds | Time | Route | Failure Reason |",
        "|---|---|---|---|---|---|---|",
    ])
    for r in summary["results"]:
        status = "\u2705" if r["success"] else "\u274c"
        md_lines.append(
            f"| {r['target_id']} | {status} | {r.get('flag', '-') or '-'} | "
            f"{r.get('rounds', 0)} | {r.get('time_seconds', 0)}s | "
            f"{r.get('winning_route', '-') or '-'} | "
            f"{r.get('failure_reason', '-') or '-'} |"
        )

    md_lines.extend([
        "",
        "---",
        f"*Generated by pytest_sessionfinish hook at {time.strftime('%Y-%m-%d %H:%M:%S')}*",
    ])

    md_path = report_dir / f"{run_id}.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    log.info("Benchmark report written to %s", report_dir)
