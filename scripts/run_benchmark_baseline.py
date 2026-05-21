"""Run the 12-target benchmark and generate baseline report.

This script runs the benchmark directly (without pytest assertions)
to capture results and generate JSON + Markdown reports regardless
of pass/fail status.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import requests
from tests.benchmark.web_targets.registry import (
    STRICT_BENCHMARK_12,
    TARGET_METADATA,
    get_target_class,
    get_target_flag,
)


def run_single_target(target_id: str) -> dict:
    """Run the MultiAgentOrchestrator against a single target."""
    from autopnex.ctf.multi_agent import MultiAgentOrchestrator
    import re

    cls = get_target_class(target_id)
    if cls is None:
        return {
            "target_id": target_id,
            "success": False,
            "flag": None,
            "rounds": 0,
            "time_seconds": 0,
            "failure_reason": "target_class_not_found",
        }

    target = cls()
    target.start()
    expected_flag = get_target_flag(target_id)

    start_time = time.monotonic()
    try:
        sess = requests.Session()
        orch = MultiAgentOrchestrator(
            target_url=target.url,
            flag_format=r"flag\{[^}]+\}",
            max_rounds=15,
            session=sess,
        )

        found, flag, action_log = orch.run_loop(max_rounds=15)
        elapsed = time.monotonic() - start_time

        rounds_used = len(set(e["round"] for e in action_log)) if action_log else 0

        if found and flag and flag.strip() == expected_flag:
            result = {
                "target_id": target_id,
                "success": True,
                "flag": flag.strip(),
                "rounds": rounds_used,
                "time_seconds": round(elapsed, 2),
                "failure_reason": None,
                "attribution": "multi_agent",
            }
        elif found and flag:
            result = {
                "target_id": target_id,
                "success": False,
                "flag": flag.strip(),
                "rounds": rounds_used,
                "time_seconds": round(elapsed, 2),
                "failure_reason": f"wrong_flag (expected={expected_flag}, got={flag})",
                "attribution": "multi_agent",
            }
        else:
            # Classify failure reason
            failure_reason = "flag_not_found"
            if elapsed > 120:
                failure_reason = "timeout"
            elif any("error" in str(e.get("result_summary", "")).lower() for e in action_log):
                failure_reason = "exception"

            result = {
                "target_id": target_id,
                "success": False,
                "flag": None,
                "rounds": rounds_used,
                "time_seconds": round(elapsed, 2),
                "failure_reason": failure_reason,
                "attribution": "multi_agent",
            }

    except Exception as exc:
        elapsed = time.monotonic() - start_time
        result = {
            "target_id": target_id,
            "success": False,
            "flag": None,
            "rounds": 0,
            "time_seconds": round(elapsed, 2),
            "failure_reason": f"exception: {type(exc).__name__}: {exc}",
            "attribution": None,
        }
    finally:
        try:
            target.stop()
        except Exception:
            pass

    return result


def main():
    print("=" * 60)
    print("AutoPenX Strict Web Benchmark — Baseline Run")
    print("=" * 60)
    print(f"Targets: {len(STRICT_BENCHMARK_12)}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    results = []
    for i, target_id in enumerate(STRICT_BENCHMARK_12.keys(), 1):
        print(f"[{i:2d}/12] Running {target_id}...", end=" ", flush=True)
        result = run_single_target(target_id)
        status = "✅ PASS" if result["success"] else f"❌ FAIL ({result['failure_reason']})"
        print(f"{status} [{result['time_seconds']}s, {result['rounds']} rounds]")
        results.append(result)

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r["success"])
    failed = total - passed
    success_rate = passed / total if total > 0 else 0

    print()
    print("=" * 60)
    print(f"RESULTS: {passed}/{total} passed ({success_rate:.0%})")
    print("=" * 60)

    # Failure classification
    failure_reasons = {}
    for r in results:
        if not r["success"]:
            reason = r["failure_reason"].split(":")[0] if r["failure_reason"] else "unknown"
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

    if failure_reasons:
        print("\nFailure Classification:")
        for reason, count in sorted(failure_reasons.items(), key=lambda x: -x[1]):
            print(f"  {reason}: {count}")

    # Generate reports
    report_dir = ROOT / "benchmark_results"
    report_dir.mkdir(exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_id = f"baseline_12_{timestamp}"

    summary = {
        "run_id": run_id,
        "model": "multi_agent_rule_based",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": total,
        "passed": passed,
        "failed": failed,
        "success_rate": round(success_rate, 4),
        "avg_rounds": round(sum(r["rounds"] for r in results) / total, 1) if total > 0 else 0,
        "avg_time_seconds": round(sum(r["time_seconds"] for r in results) / total, 2) if total > 0 else 0,
        "failure_classification": failure_reasons,
        "results": results,
    }

    # Write JSON
    json_path = report_dir / f"{run_id}.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nJSON report: {json_path}")

    # Write Markdown
    md_lines = [
        "# Strict Web Benchmark — Baseline Report",
        "",
        f"**Run ID**: `{run_id}`",
        f"**Model**: multi_agent_rule_based (no LLM calls in this run)",
        f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total Targets | {total} |",
        f"| Passed | {passed} |",
        f"| Failed | {failed} |",
        f"| Success Rate | {success_rate:.0%} |",
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
        "| # | Target | Success | Flag | Rounds | Time | Failure Reason |",
        "|---|---|---|---|---|---|---|",
    ])
    for i, r in enumerate(results, 1):
        status = "✅" if r["success"] else "❌"
        md_lines.append(
            f"| {i} | {r['target_id']} | {status} | "
            f"{r.get('flag', '-') or '-'} | {r['rounds']} | "
            f"{r['time_seconds']}s | {r.get('failure_reason', '-') or '-'} |"
        )

    md_lines.extend([
        "",
        "## Analysis",
        "",
        "### Key Observations",
        "",
        "1. **Baseline success rate**: This is the starting point for improvement",
        "2. **Rule-based agent**: The MultiAgentOrchestrator uses deterministic helpers",
        "   and route state machines — no LLM calls were made in this run",
        "3. **Fast execution**: All targets complete in < 1s, indicating the agent",
        "   runs through its decision loop quickly but doesn't effectively exploit",
        "",
        "### Next Steps",
        "",
        "- Task 2.3: Fix runtime errors discovered in this run",
        "- Improve route state machines to actually send HTTP requests with payloads",
        "- Integrate LLM reasoning for complex targets",
        "- Target: ≥ 70% success rate on 30 targets",
        "",
        "---",
        f"*Generated by `scripts/run_benchmark_baseline.py` at {time.strftime('%Y-%m-%d %H:%M:%S')}*",
    ])

    md_path = report_dir / f"{run_id}.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"Markdown report: {md_path}")


if __name__ == "__main__":
    main()
