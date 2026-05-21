"""Pytest fixtures for strict web benchmark — manages challenge server lifecycle.

Each benchmark target is a self-contained HTTP server (stdlib http.server)
started on a random free port. Tests connect to these servers via their
local URL and exercise the actual agent's solve path.

No Docker required — these are pure Python HTTP servers.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Generator, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.benchmark.challenges import ChallengeTarget
from tests.benchmark.web_targets.registry import (
    STRICT_BENCHMARK_12,
    get_target_class,
    get_target_metadata,
    get_target_flag,
)

log = logging.getLogger("autopnex.benchmark.web_targets")


# ---------------------------------------------------------------------------
# Target lifecycle fixtures
# (Note: benchmark_target fixture is defined in tests/benchmark/conftest.py)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# LLM availability detection
# ---------------------------------------------------------------------------

_llm_checked: Optional[bool] = None


def _llm_available() -> bool:
    """Check if DeepSeek API is available.

    First checks DEEPSEEK_API_KEY environment variable directly,
    then falls back to config.settings. Does NOT make a real API call
    during test collection — only checks if the key is configured.
    """
    global _llm_checked
    if _llm_checked is not None:
        return _llm_checked

    # Fast path: check environment variable directly
    env_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if env_key:
        _llm_checked = True
        return True

    # Fallback: check config.settings
    try:
        from config.settings import settings
        if settings.deepseek_api_key:
            _llm_checked = True
            return True
    except Exception as e:
        log.debug("Could not load config.settings: %s", e)

    _llm_checked = False
    return False


# ---------------------------------------------------------------------------
# Benchmark report generation hook
# ---------------------------------------------------------------------------

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
        status = "✅" if r["success"] else "❌"
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
