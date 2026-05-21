"""Exploration benchmark — diagnoses agent capability on UNREGISTERED targets.

This test is INTENTIONALLY non-strict. It runs the existing
MultiAgentOrchestrator against the 21 ChallengeTarget classes that exist
in challenges.py but are NOT part of STRICT_BENCHMARK_12.

Goal: identify which targets the agent can already solve (candidates for
promotion to a future STRICT_BENCHMARK_24/30) and which targets reveal
real capability gaps (candidates for RouteStateMachine / RouteCards
enhancement).

Marker: `explore_benchmark`  (not collected by default).

Run:
    pytest tests/benchmark/test_web_benchmark_explore.py -m explore_benchmark
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import pytest
import requests

from tests.benchmark.challenges import (
    ChallengeTarget,
    SourceLeakBackupZip,
    SourceLeakEnvFile,
    LFIReadPhpFilter,
    SSTITwigFiltered,
    SSTISmartyFiltered,
    SQLiErrorBased,
    SQLiTimeBlind,
    CMDiBasicSemicolon,
    CMDiNoEcho,
    SSRFLocalhostFlag,
    SSRFCloudMetadata,
    SSRFFileProtocol,
    JWTWeakKey,
    JWTKidInjection,
    UploadMimeCheck,
    UploadDoubleExt,
    UploadHtaccess,
    PHPPopUnserializeCookie,
    PHPPopPharTrigger,
    IDORNumeric,
    IDORUUID,
)

log = logging.getLogger("autopnex.benchmark.explore")


# ---------------------------------------------------------------------------
# Exploration registry — 21 targets implemented in challenges.py but
# NOT part of STRICT_BENCHMARK_12.
# ---------------------------------------------------------------------------

EXPLORE_BENCHMARK_21: Dict[str, Type[ChallengeTarget]] = {
    # source_leak (2 extra)
    "source_leak_backup_zip": SourceLeakBackupZip,
    "source_leak_env_file":   SourceLeakEnvFile,
    # lfi (1 extra)
    "lfi_php_filter":         LFIReadPhpFilter,
    # ssti (2 extra)
    "ssti_twig":              SSTITwigFiltered,
    "ssti_smarty":            SSTISmartyFiltered,
    # sqli (2 extra)
    "sqli_error":             SQLiErrorBased,
    "sqli_time_blind":        SQLiTimeBlind,
    # cmdi (2 extra)
    "cmdi_semicolon":         CMDiBasicSemicolon,
    "cmdi_no_echo":           CMDiNoEcho,
    # ssrf (3 new)
    "ssrf_localhost":         SSRFLocalhostFlag,
    "ssrf_metadata":          SSRFCloudMetadata,
    "ssrf_file_proto":        SSRFFileProtocol,
    # jwt (2 extra)
    "jwt_weak_key":           JWTWeakKey,
    "jwt_kid_injection":      JWTKidInjection,
    # upload (3 new)
    "upload_mime":            UploadMimeCheck,
    "upload_double_ext":      UploadDoubleExt,
    "upload_htaccess":        UploadHtaccess,
    # php_pop (2 new)
    "php_pop_cookie":         PHPPopUnserializeCookie,
    "php_pop_phar":           PHPPopPharTrigger,
    # idor (2 new)
    "idor_numeric":           IDORNumeric,
    "idor_uuid":              IDORUUID,
}


# ---------------------------------------------------------------------------
# Single-target run (mirrors test_web_benchmark._run_agent_against_target)
# ---------------------------------------------------------------------------

def _run_agent(target: ChallengeTarget, target_id: str, max_rounds: int = 15) -> Dict[str, Any]:
    from autopnex.ctf.multi_agent import MultiAgentOrchestrator

    expected_flag = target.flag
    start = time.monotonic()
    try:
        sess = requests.Session()
        orch = MultiAgentOrchestrator(
            target_url=target.url,
            flag_format=r"flag\{[^}]+\}",
            max_rounds=max_rounds,
            session=sess,
        )
        found, flag, action_log = orch.run_loop(max_rounds=max_rounds)
        elapsed = time.monotonic() - start
        rounds_used = len(set(e["round"] for e in action_log)) if action_log else 0
        flag_val = (flag or "").strip()

        if found and flag_val == expected_flag:
            return _build_result(target_id, True, flag_val, rounds_used, elapsed,
                                 action_log, expected_flag, None)
        if found and flag_val:
            return _build_result(target_id, False, flag_val, rounds_used, elapsed,
                                 action_log, expected_flag,
                                 f"wrong_flag: expected {expected_flag} got {flag_val}")
        return _build_result(target_id, False, None, rounds_used, elapsed,
                             action_log, expected_flag, "flag_not_found")
    except Exception as exc:
        elapsed = time.monotonic() - start
        log.exception("explore[%s] crashed: %s", target_id, exc)
        return _build_result(target_id, False, None, 0, elapsed,
                             [], expected_flag, f"exception: {type(exc).__name__}: {exc}")


def _build_result(
    target_id: str,
    success: bool,
    flag: Optional[str],
    rounds: int,
    elapsed: float,
    action_log: List[Dict[str, Any]],
    expected_flag: str,
    failure_reason: Optional[str],
) -> Dict[str, Any]:
    winning_route: Optional[str] = None
    if success and action_log:
        for entry in reversed(action_log):
            decision = entry.get("decision") or {}
            route = decision.get("route") or ""
            if route and route not in ("recon", "critic", "flag_verify"):
                winning_route = route
                break

    actions = []
    for entry in action_log:
        decision = entry.get("decision") or {}
        na = decision.get("next_action") or {}
        actions.append(f"{na.get('action')}:{na.get('route')}")
    repeat_ratio = 0.0
    if actions:
        repeat_ratio = round(1.0 - (len(set(actions)) / len(actions)), 2)

    return {
        "target_id": target_id,
        "success": success,
        "flag": flag,
        "expected_flag": expected_flag,
        "rounds": rounds,
        "time_seconds": round(elapsed, 2),
        "winning_route": winning_route,
        "failure_reason": failure_reason,
        "repeat_ratio": repeat_ratio,
    }


# ---------------------------------------------------------------------------
# Per-target lifecycle fixture (local to explore module)
# ---------------------------------------------------------------------------

@pytest.fixture
def explore_target(request):
    target_id = request.param
    cls = EXPLORE_BENCHMARK_21[target_id]
    target = cls()
    target.start()
    # small grace period for the http server thread to be ready
    time.sleep(0.05)
    yield target_id, target
    try:
        target.stop()
    except Exception:
        pass
    try:
        target.cleanup()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Parametrized exploration test — DOES NOT FAIL on agent miss.
# ---------------------------------------------------------------------------

_explore_results: Dict[str, Dict[str, Any]] = {}


@pytest.mark.explore_benchmark
@pytest.mark.parametrize("explore_target", list(EXPLORE_BENCHMARK_21.keys()), indirect=True)
def test_explore_benchmark(explore_target, request):
    target_id, target = explore_target
    result = _run_agent(target, target_id)
    _explore_results[target_id] = result
    if hasattr(request.node, "config"):
        request.node.config._explore_results = _explore_results

    # Soft assertion: ALWAYS passes. The point is the report, not the verdict.
    # We log the outcome and let pytest_sessionfinish write the report.
    status = "PASS" if result["success"] else "MISS"
    log.warning(
        "[explore] %-25s %s rounds=%d time=%.2fs route=%s reason=%s",
        target_id, status, result["rounds"], result["time_seconds"],
        result["winning_route"] or "-", result["failure_reason"] or "-",
    )
    assert True  # never fail


# ---------------------------------------------------------------------------
# Report writer (session-scoped autouse fixture - reliably runs at end)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _write_explore_report():
    yield
    _emit_report()


def _emit_report() -> None:
    results = _explore_results
    if not results:
        return

    report_dir = Path(__file__).resolve().parent.parent.parent / "benchmark_results"
    report_dir.mkdir(exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_id = f"explore_21_{timestamp}"

    total = len(results)
    passed = sum(1 for r in results.values() if r["success"])
    failed = total - passed

    summary = {
        "run_id": run_id,
        "model": "multi_agent_rule_based",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": total,
        "passed": passed,
        "failed": failed,
        "success_rate": round(passed / total, 4) if total else 0,
        "avg_rounds": round(sum(r["rounds"] for r in results.values()) / total, 1) if total else 0,
        "avg_time_seconds": round(sum(r["time_seconds"] for r in results.values()) / total, 2) if total else 0,
        "results": list(results.values()),
    }

    json_path = report_dir / f"{run_id}.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    md_lines = [
        "# Exploration Benchmark Report (unregistered targets)",
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
        "## Per-Target Results",
        "",
        "| Target | Result | Flag | Rounds | Time | Route | Failure Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results.values():
        status = "PASS" if r["success"] else "MISS"
        md_lines.append(
            f"| {r['target_id']} | {status} | {r.get('flag') or '-'} | "
            f"{r.get('rounds', 0)} | {r.get('time_seconds', 0)}s | "
            f"{r.get('winning_route') or '-'} | {r.get('failure_reason') or '-'} |"
        )
    md_lines.extend([
        "",
        "## Interpretation",
        "",
        "- **PASS** -> candidate for promotion to STRICT_BENCHMARK_24/30",
        "- **MISS** -> capability gap; failure_reason hints what RouteStateMachine / RouteCards / helpers should add",
        "",
    ])
    md_path = report_dir / f"{run_id}.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    log.info("Exploration benchmark report written to %s", report_dir)
    print(f"\n[explore] report -> {json_path}")
    print(f"[explore] report -> {md_path}")
