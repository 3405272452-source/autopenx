"""
Standalone benchmark runner for AutoPenX.

Usage:
  python -m tests.benchmark.run_benchmark --target dvwa --mode single_agent
  python -m tests.benchmark.run_benchmark --target dvwa --mode multi_agent
  python -m tests.benchmark.run_benchmark --target all --mode both
  python -m tests.benchmark.run_benchmark --target dvwa --mode single_agent --output reports/bench.json
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import settings
from autopnex.orchestrator import LLMOrchestrator
from autopnex.state_machine.machine import PenTestStateMachine

from tests.benchmark.docker_targets import TARGETS, TargetManager, docker_available
from tests.benchmark.expected_vulns import get_expected
from tests.benchmark.metrics import BenchmarkResult, MetricsCollector

log = logging.getLogger("autopnex.benchmark")


def run_benchmark(
    target_name: str,
    mode: str,
    *,
    max_iter: int = 6,
    skip_docker: bool = False,
) -> BenchmarkResult:
    """Run a full benchmark against a single target.

    Parameters
    ----------
    target_name:
        Name of the vulnerable target (dvwa, juice-shop, webgoat).
    mode:
        "single_agent" or "multi_agent".
    max_iter:
        Maximum iterations per state-machine phase.
    skip_docker:
        If True, assume the target is already running.
    """
    expected = get_expected(target_name)
    target_info = TARGETS[target_name]
    collector = MetricsCollector(target_name, expected, mode=mode)

    manager = TargetManager()
    started_docker = False

    try:
        if not skip_docker:
            if not docker_available():
                log.error("Docker is not available — cannot start %s", target_name)
                return collector.compute()
            log.info("Starting Docker target %s ...", target_name)
            manager.start_and_wait(target_name, timeout=90)
            started_docker = True
        else:
            log.info("Skipping Docker — assuming %s is already running at %s", target_name, target_info.url)

        runtime = settings.snapshot(
            allow_local_targets=True,
            exploit_enabled=True,
            allow_external_tools=False,
            max_iter_per_state=max_iter,
        )
        is_multi = mode == "multi_agent"
        orchestrator = LLMOrchestrator(
            mock=not runtime.has_llm,
            runtime_config=runtime,
        )

        progress_events: List[dict] = []

        def _on_progress(event: dict) -> None:
            progress_events.append(event)
            evt = event.get("event", "")
            state = event.get("state", "")
            if evt in ("state_enter", "state_exit", "start", "done"):
                log.info("[%s] %s  state=%s", target_name, evt, state)
            elif evt == "react_step":
                log.info(
                    "[%s] step %s  tool=%s  success=%s",
                    target_name,
                    event.get("iteration"),
                    event.get("tool"),
                    event.get("tool_success"),
                )

        sm = PenTestStateMachine(
            target_info.url,
            orchestrator,
            multi_agent=is_multi,
            max_iter_per_state=max_iter,
            progress_callback=_on_progress,
        )

        log.info("Running %s scan on %s ...", mode, target_name)
        t0 = time.monotonic()
        findings = sm.run()
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        collector.record_findings(findings)
        result = collector.compute()
        result.total_duration_ms = elapsed_ms
        return result

    finally:
        if started_docker:
            manager.stop(target_name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AutoPenX benchmark runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        choices=["dvwa", "juice-shop", "webgoat", "all"],
        default="dvwa",
        help="Vulnerable target to benchmark against (default: dvwa)",
    )
    parser.add_argument(
        "--mode",
        choices=["single_agent", "multi_agent", "both"],
        default="single_agent",
        help="Agent mode to use (default: single_agent)",
    )
    parser.add_argument(
        "--output",
        default="reports/benchmark.json",
        help="Output JSON file for results (default: reports/benchmark.json)",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=6,
        help="Maximum iterations per FSM phase (default: 6)",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Assume targets are already running (skip Docker lifecycle)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    targets = list(TARGETS) if args.target == "all" else [args.target]
    modes = (
        ["single_agent", "multi_agent"] if args.mode == "both"
        else [args.mode]
    )

    results: List[BenchmarkResult] = []

    for target_name in targets:
        for mode in modes:
            log.info("=" * 60)
            log.info("Benchmark: %s / %s", target_name, mode)
            log.info("=" * 60)
            result = run_benchmark(
                target_name,
                mode,
                max_iter=args.max_iter,
                skip_docker=args.skip_docker,
            )
            results.append(result)
            print(result.summary())

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [r.to_dict() for r in results]
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Results saved to %s", output_path)

    print("\n" + "=" * 60)
    print(f"  {len(results)} benchmark(s) complete. Output: {output_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
