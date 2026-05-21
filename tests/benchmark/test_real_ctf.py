"""Real CTF challenge test — runs agent against simulated BUUCTF challenges.

Marker: `real_ctf` (not collected by default).

Run:
    pytest tests/benchmark/test_real_ctf.py -m real_ctf -v -s
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import requests

from tests.benchmark.real_ctf_targets import REAL_CTF_TARGETS

log = logging.getLogger("autopnex.benchmark.real_ctf")

# ---------------------------------------------------------------------------
# Scenario mapping: target_id → expected scenario
# ---------------------------------------------------------------------------

_TARGET_SCENARIO_MAP: Dict[str, str] = {
    "geek2019_easysql": "sqli.login_bypass",
    "geek2019_upload": "upload.extension_bypass",
    "hctf2018_warmup": "lfi.whitelist_bypass",
    "geek2019_php": "php_pop.unserialize_chain",
    "suctf2019_easysql": "sqli.stacked_handler",
    "qwb2019_random_inject": "sqli.random_inject",
    "gyctf2020_blacklist": "sqli.blacklist_bypass",
    "geek2019_babysql": "sqli.double_write_bypass",
    "geek2019_secretfile": "lfi.php_filter",
    "actf2020_include": "lfi.php_filter_include",
    "bjdctf2020_easymd5": "sqli.md5_bypass",
    "hwb2018_easy_tornado": "ssti.tornado_handler",
    "geek2019_buyflag": "auth.cookie_manipulation",
    "geek2019_http": "auth.header_spoofing",
    "geek2019_easyphp": "php_pop.type_juggling",
    "wdb2020_areuserialz": "php_pop.serialize_bypass",
    "de1ctf2019_ssrfme": "ssrf.flask_local",
    "nctf2019_truexml": "xxe.entity_injection",
    "gxyctf2019_pingpingping": "cmdi.space_bypass",
    "geek2019_rceme": "cmdi.non_alpha_rce",
    "roarctf2019_easycalc": "cmdi.waf_bypass_calc",
    "geek2019_knife": "cmdi.webshell_direct",
    "geek2019_lovesql": "sqli.union_login",
    "mrctf2020_ezbypass": "php_pop.md5_array_bypass",
    "zjctf2019_nizhuan": "lfi.data_stream_filter",
    "ciscn2019_hackworld": "sqli.boolean_blind",
    "geek2019_hardsql": "sqli.error_based_extractvalue",
    "wdb2018_fakebook": "sqli.union_ssrf",
    "bsides2020_badday": "lfi.category_filter",
    "geek2019_finalsql": "sqli.xor_blind",
}


def _run_agent(target, target_id: str, max_rounds: int = 15) -> Dict[str, Any]:
    from autopnex.ctf.multi_agent import MultiAgentOrchestrator

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
        rounds_used = len(set(e.get("round", 0) for e in action_log)) if action_log else 0
        flag_val = (flag or "").strip()

        success = found and flag_val == target.flag

        result = {
            "target_id": target_id,
            "success": success,
            "flag": flag_val,
            "expected_flag": target.flag,
            "rounds": rounds_used,
            "time_seconds": round(elapsed, 2),
            "failure_reason": None if success else (
                f"wrong_flag: got {flag_val}" if flag_val else "flag_not_found"
            ),
            "winning_route": "",
            "scenario": _TARGET_SCENARIO_MAP.get(target_id, ""),
            "repeat_ratio": 0.0,
        }

        # Try to extract winning route from orchestrator state
        try:
            state = orch.get_state_summary()
            if state and isinstance(state, dict):
                # Find the route that succeeded
                route_status = state.get("route_status", {})
                for route, status in route_status.items():
                    if status == "succeeded":
                        result["winning_route"] = route
                        break
        except Exception:
            pass

        # Dump debug snapshot on failure
        if not success:
            _dump_debug_snapshot(target_id, orch)

        return result
    except Exception as exc:
        elapsed = time.monotonic() - start
        return {
            "target_id": target_id,
            "success": False,
            "flag": None,
            "expected_flag": target.flag,
            "rounds": 0,
            "time_seconds": round(elapsed, 2),
            "failure_reason": f"exception: {type(exc).__name__}: {exc}",
            "winning_route": "",
            "scenario": _TARGET_SCENARIO_MAP.get(target_id, ""),
            "repeat_ratio": 0.0,
        }


def _dump_debug_snapshot(target_id: str, orch) -> None:
    """Save debug snapshot of blackboard state on failure."""
    try:
        debug_dir = Path(__file__).resolve().parent.parent.parent / "benchmark_results" / "debug"
        debug_dir.mkdir(parents=True, exist_ok=True)
        state = orch.get_state_summary()
        if state:
            debug_path = debug_dir / f"{target_id}_blackboard.json"
            debug_path.write_text(
                json.dumps(state, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
    except Exception:
        pass  # Non-critical — don't fail the test


@pytest.fixture
def real_target(request):
    target_id = request.param
    cls = REAL_CTF_TARGETS[target_id]
    target = cls()
    target.start()
    time.sleep(0.05)
    yield target_id, target
    try:
        target.stop()
    except Exception:
        pass


_results: Dict[str, Dict[str, Any]] = {}


@pytest.mark.real_ctf
@pytest.mark.parametrize("real_target", list(REAL_CTF_TARGETS.keys()), indirect=True)
def test_real_ctf(real_target):
    target_id, target = real_target
    result = _run_agent(target, target_id)
    _results[target_id] = result

    status = "PASS" if result["success"] else "MISS"
    print(
        f"\n  [{status}] {target_id}: rounds={result['rounds']} "
        f"time={result['time_seconds']}s flag={result.get('flag', '-')}"
    )
    if not result["success"]:
        print(f"         reason: {result['failure_reason']}")
        print(f"         expected: {result['expected_flag']}")


def _write_coverage_report(results: Dict[str, Dict[str, Any]], report_dir: Path) -> None:
    """Write scenario coverage report mapping each target to pass/fail."""
    scenario_coverage: Dict[str, str] = {}
    for target_id, result in results.items():
        scenario = _TARGET_SCENARIO_MAP.get(target_id, f"unknown.{target_id}")
        scenario_coverage[scenario] = "pass" if result["success"] else "fail"

    coverage = {"scenario_coverage": scenario_coverage}
    coverage_path = report_dir / "coverage_report.json"
    coverage_path.write_text(
        json.dumps(coverage, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


@pytest.fixture(scope="session", autouse=True)
def _write_report():
    yield
    if not _results:
        return
    report_dir = Path(__file__).resolve().parent.parent.parent / "benchmark_results"
    report_dir.mkdir(exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    total = len(_results)
    passed = sum(1 for r in _results.values() if r["success"])

    # Determine run mode
    run_mode = "full" if total >= 20 else "single"

    summary = {
        "run_id": f"real_ctf_{timestamp}",
        "suite": "real_ctf_20",
        "run_mode": run_mode,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "success_rate": round(passed / total, 2) if total else 0,
        "results": list(_results.values()),
    }

    json_path = report_dir / f"real_ctf_{timestamp}.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n\nReal CTF Report: {passed}/{total} passed")
    print(f"Report: {json_path}")

    # Write coverage report
    _write_coverage_report(_results, report_dir)
