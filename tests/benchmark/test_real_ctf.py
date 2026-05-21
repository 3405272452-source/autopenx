"""Real CTF challenge test — runs agent against simulated BUUCTF challenges.

Marker: `real_ctf` (not collected by default).

Run:
    pytest tests/benchmark/test_real_ctf.py -m real_ctf -v -s
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import requests

from tests.benchmark.real_ctf_targets import REAL_CTF_TARGETS

log = logging.getLogger("autopnex.benchmark.real_ctf")


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

        return {
            "target_id": target_id,
            "success": found and flag_val == target.flag,
            "flag": flag_val,
            "expected_flag": target.flag,
            "rounds": rounds_used,
            "time_seconds": round(elapsed, 2),
            "failure_reason": None if (found and flag_val == target.flag) else (
                f"wrong_flag: got {flag_val}" if flag_val else "flag_not_found"
            ),
        }
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
        }


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

    summary = {
        "run_id": f"real_ctf_{timestamp}",
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
