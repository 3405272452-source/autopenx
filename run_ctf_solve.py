"""Unified CTF solver CLI — single orchestration entry point.

Routes all solves through CTFSolvePipeline (Phase 1 → Phase 2 → Phase 3),
avoiding the dual-maintenance trap of calling CTFReActAgent directly.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv()

from config.settings import settings

settings.reload()

from autopnex.ctf.solve_pipeline import CTFSolvePipeline, PipelineConfig, SolveResult


def progress_callback(event: dict):
    """Print structured progress events to stdout."""
    ev_type = event.get("event", "")
    if ev_type == "ctf_iteration_start":
        print(f"\n--- Iteration {event.get('iteration')}/{event.get('max_iterations')} ---")
    elif ev_type == "ctf_tool_start":
        args_str = json.dumps(event.get("arguments", {}), ensure_ascii=False)[:150]
        print(f"  [TOOL] {event.get('tool')}({args_str})")
    elif ev_type == "ctf_tool_finish":
        preview = str(event.get("result_preview", ""))[:200]
        print(f"  [RESULT] {preview}")
    elif ev_type == "ctf_helper_triggered":
        print(f"  [HELPER] {event.get('helper')} @ {event.get('url', '')[:80]}")
    elif ev_type == "ctf_fuse_triggered":
        print(f"  [FUSE] {event.get('level')}: {event.get('reason', '')[:100]}")
    elif ev_type == "ctf_evidence_card":
        print(f"  [EVIDENCE] {event.get('summary', '')[:100]}")
    elif ev_type in ("ctf_error",):
        print(f"  [ERROR] {event.get('error_type', '')}: {event.get('tool', '')}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AutoPenX CTF Solver — unified pipeline (Phase 1→2→3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python run_ctf_solve.py --target http://example.com:8080\n"
            "  python run_ctf_solve.py --target http://example.com --challenge-type pwn --flag-format 'ctf\\{[^}]+\\}'\n"
            "  python run_ctf_solve.py --target http://example.com --timeout 120 --max-iterations 20\n"
        ),
    )
    p.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL to attack (e.g. http://challenge.example.com:8080)",
    )
    p.add_argument(
        "--challenge-type", "-c",
        default="web",
        choices=["web", "pwn", "reverse", "crypto", "misc", "forensics"],
        help="Challenge category (default: web)",
    )
    p.add_argument(
        "--flag-format", "-f",
        default=r"flag\{[^}]+\}",
        help="Regex pattern to match flags (default: flag\\{[^}]+\\})",
    )
    p.add_argument(
        "--max-iterations", "-n",
        type=int,
        default=30,
        help="Max ReAct iterations in Phase 3 (default: 30)",
    )
    p.add_argument(
        "--timeout", "-T",
        type=int,
        default=600,
        help="Total wall-clock timeout in seconds (default: 600)",
    )
    p.add_argument(
        "--no-thinking",
        action="store_true",
        help="Disable LLM extended thinking mode",
    )
    p.add_argument(
        "--no-multi-agent",
        action="store_true",
        help="Disable multi-agent hybrid solving (Phase 1 deterministic routes)",
    )
    p.add_argument(
        "--kb-path",
        default=str(PROJECT_ROOT / "ctf_knowledge.json"),
        help="Path to CTF knowledge base JSON (default: ./ctf_knowledge.json)",
    )
    p.add_argument(
        "--parallel-scan",
        action="store_true",
        default=False,
        help="Enable parallel route scanning in Phase 1",
    )
    p.add_argument(
        "--phase1-mode",
        choices=["multi_agent", "parallel_scan", "hybrid"],
        default="hybrid",
        help="Phase 1 execution mode (default: hybrid)",
    )
    p.add_argument(
        "--no-experience",
        action="store_true",
        default=False,
        help="Disable experience writing after solve",
    )
    p.add_argument(
        "--output", "-o",
        default=None,
        help="Path to write JSON result summary",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    return p


async def solve(args: argparse.Namespace) -> SolveResult:
    """Instantiate the pipeline and run all three phases."""
    runtime = settings.snapshot()

    pipeline_config = PipelineConfig(
        phase3_max_iterations=args.max_iterations,
        phase3_wall_clock_timeout_seconds=float(args.timeout),
        knowledge_path=args.kb_path,
        phase1_mode="parallel_scan" if args.parallel_scan else args.phase1_mode,
        experience_write_enabled=not args.no_experience,
    )

    pipeline = CTFSolvePipeline(
        config=pipeline_config,
        target=args.target,
        session=None,
        blackboard=None,
        flag_engine=None,
        runtime_config=runtime,
    )

    cb = None if args.quiet else progress_callback

    result = await pipeline.run()
    return result


def print_result(result: SolveResult, elapsed: float):
    """Pretty-print the SolveResult."""
    print("\n" + "=" * 60)
    print(f"Success:       {result.success}")
    print(f"Flag:          {result.flag or '(none)'}")
    print(f"Phase:         {result.solving_phase}")
    print(f"Duration:      {elapsed:.1f}s ({result.duration_ms:.0f}ms pipeline)")
    print(f"Phase 1 rnds:  {result.phase1_rounds}")
    print(f"Phase 2 turns: {result.phase2_turns}")
    print(f"Phase 3 iters: {result.phase3_iterations}")
    if result.error:
        print(f"Error:         {result.error}")
    if result.upgrade_events:
        print(f"\nUpgrade transitions ({len(result.upgrade_events)}):")
        for ev in result.upgrade_events:
            print(f"  {ev.get('from_phase')} → {ev.get('to_phase')}: {ev.get('reason', '')}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    start = time.time()
    try:
        result = asyncio.run(solve(args))
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(130)
    elapsed = time.time() - start

    print_result(result, elapsed)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result.to_json(), encoding="utf-8")
        print(f"\nResult written to {out_path}")

    if not result.success and result.error == "llm_unavailable":
        print("\nHint: set DEEPSEEK_API_KEY in .env to enable LLM-driven phases.")
        sys.exit(2)

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
