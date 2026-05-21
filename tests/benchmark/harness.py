"""Benchmark harness for Web CTF challenge evaluation.

Runs challenges through the ReAct agent (not mock LLM), collects
structured results, and produces JSON/Markdown reports.

Report fields per roadmap 9.4:
  challenge, success, flag, rounds, elapsed_seconds, token_estimate,
  routes_tried, winning_route, completion_type, llm_key_decisions,
  helper_key_decisions, failure_reason, replay_log
"""

from __future__ import annotations

import json
import logging
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("autopnex.benchmark")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkRun:
    """Result of a single challenge run."""
    challenge: str
    success: bool
    flag: Optional[str] = None
    rounds: int = 0
    elapsed_seconds: float = 0.0
    token_estimate: int = 0
    routes_tried: List[str] = field(default_factory=list)
    winning_route: str = ""
    completion_type: str = ""          # route_state_machine | llm_decision | helper | manual
    llm_key_decisions: int = 0
    helper_key_decisions: int = 0
    failure_reason: Optional[str] = None
    replay_log: str = ""               # Path to replay file
    error: Optional[str] = None        # Unexpected error during run


@dataclass
class BenchmarkReport:
    """Aggregated benchmark report."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    total_challenges: int = 0
    successful: int = 0
    failed: int = 0
    errored: int = 0
    success_rate: float = 0.0
    avg_rounds: float = 0.0
    avg_elapsed_seconds: float = 0.0
    avg_token_estimate: float = 0.0
    repeat_action_rate: float = 0.0
    runs: List[BenchmarkRun] = field(default_factory=list)

    # Per-category stats
    category_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Failure analysis
    failure_reasons: Dict[str, int] = field(default_factory=dict)
    top_routes: Dict[str, int] = field(default_factory=dict)  # route -> success count


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class BenchmarkHarness:
    """Runs multiple CTF challenges and produces structured benchmark reports.

    Usage:
        harness = BenchmarkHarness(output_dir="bench_results/")
        harness.add_challenge(MyChallenge())
        report = harness.run_all(parallel=False)
        harness.save_report(report)
    """

    def __init__(
        self,
        output_dir: str = "bench_results",
        max_iterations: int = 15,
        timeout_per_challenge: int = 300,
        thinking: bool = True,
        skip_tests: Optional[List[str]] = None,
        only_tests: Optional[List[str]] = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_iterations = max_iterations
        self.timeout_per_challenge = timeout_per_challenge
        self.thinking = thinking
        self.skip_tests = set(skip_tests or [])
        self.only_tests = set(only_tests or [])
        self.challenges: List[Tuple[type, str]] = []  # (challenge_class, challenge_id)

    def add_challenge(self, challenge_cls: type, challenge_id: str) -> None:
        """Register a challenge target."""
        self.challenges.append((challenge_cls, challenge_id))

    def add_all(self, challenges: Dict[str, type]) -> None:
        """Register all challenges from a name→class mapping."""
        for cid, cls in challenges.items():
            self.add_challenge(cls, cid)

    def run_all(self, parallel: bool = False) -> BenchmarkReport:
        """Run all registered challenges."""
        report = BenchmarkReport()
        report.total_challenges = len(self.challenges)

        for i, (challenge_cls, cid) in enumerate(self.challenges):
            if self.skip_tests and cid in self.skip_tests:
                log.info("Skipping %s", cid)
                continue
            if self.only_tests and cid not in self.only_tests:
                log.info("Skipping %s (not in --only)", cid)
                continue

            log.info("Running challenge %d/%d: %s", i + 1, len(self.challenges), cid)
            run = self._run_one(challenge_cls, cid)
            report.runs.append(run)

            if run.success:
                report.successful += 1
            elif run.error:
                report.errored += 1
            else:
                report.failed += 1

            # Update failure aggregation
            if run.failure_reason:
                reason_key = run.failure_reason.split(":")[0][:60]
                report.failure_reasons[reason_key] = report.failure_reasons.get(reason_key, 0) + 1

            # Update route stats
            if run.winning_route:
                report.top_routes[run.winning_route] = report.top_routes.get(run.winning_route, 0) + 1

            # Category stats
            category = self._category_from_id(cid)
            if category not in report.category_stats:
                report.category_stats[category] = {
                    "total": 0, "successful": 0, "failed": 0, "avg_rounds": 0.0
                }
            cat = report.category_stats[category]
            cat["total"] += 1
            if run.success:
                cat["successful"] += 1
                cat["avg_rounds"] = (cat["avg_rounds"] * (cat["total"] - 1) + run.rounds) / cat["total"]
            else:
                cat["failed"] += 1

        # Compute aggregate stats
        completed = [r for r in report.runs if r.rounds > 0]
        if completed:
            report.success_rate = report.successful / max(len(report.runs), 1)
            report.avg_rounds = sum(r.rounds for r in report.runs) / max(len(report.runs), 1)
            report.avg_elapsed_seconds = sum(r.elapsed_seconds for r in report.runs) / max(len(report.runs), 1)
            report.avg_token_estimate = sum(r.token_estimate for r in report.runs) / max(len(report.runs), 1)

        return report

    def _run_one(self, challenge_cls: type, challenge_id: str) -> BenchmarkRun:
        """Run a single challenge through the ReAct agent."""
        run = BenchmarkRun(challenge=challenge_id)
        start_time = time.time()

        try:
            # Instantiate and start challenge target
            challenge = challenge_cls()
            target_url = challenge.start()
            flag_format = getattr(challenge, "flag_format", r"[A-Za-z0-9_]+\{[^}]+\}")
            known_flag = getattr(challenge, "flag", None)

            # Import agent here to avoid circular imports
            from autopnex.ctf.react_agent import CTFReActAgent

            agent = CTFReActAgent(
                target=target_url,
                challenge_type="web",
                flag_format=flag_format,
                max_iterations=self.max_iterations,
                timeout=self.timeout_per_challenge,
                thinking=self.thinking,
            )

            # Run the agent (synchronous solve)
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(agent.solve())
            finally:
                loop.close()

            run.elapsed_seconds = time.time() - start_time
            run.rounds = len(agent._steps)
            run.success = result.get("success", False)
            run.flag = result.get("flag")
            run.failure_reason = result.get("error") if not run.success else None

            # Track routes tried
            run.routes_tried = agent._strategy._route_history if hasattr(agent._strategy, "_route_history") else []
            if agent._current_route and agent._current_route != "recon":
                run.routes_tried.append(agent._current_route)
            if run.routes_tried:
                run.winning_route = run.routes_tried[-1] if run.success else run.routes_tried[0]

            # Completion type
            run.completion_type = "route_state_machine" if run.success else "llm_decision"
            run.llm_key_decisions = sum(1 for s in agent._steps if "error" not in s)
            run.helper_key_decisions = sum(
                1 for s in agent._steps if s.get("helper_triggered")
            )

            # Verify flag if known
            if run.success and known_flag and run.flag != known_flag:
                run.failure_reason = f"Flag mismatch: expected {known_flag}, got {run.flag}"
                run.success = False

        except Exception as e:
            run.elapsed_seconds = time.time() - start_time
            run.error = f"{type(e).__name__}: {e}"
            run.failure_reason = run.error
            log.error("Challenge %s errored: %s", challenge_id, e)
            traceback.print_exc()

        finally:
            # Always cleanup challenge
            try:
                challenge.stop()
            except Exception:
                pass

        return run

    @staticmethod
    def _category_from_id(challenge_id: str) -> str:
        """Extract category from challenge ID (e.g., 'lfi_php_filter_01' -> 'lfi')."""
        parts = challenge_id.split("_")
        if len(parts) >= 2:
            # Handle multi-word categories
            if parts[0] == "source":
                return "source_leak"
            if parts[0] == "php":
                return "php_pop"
        return parts[0] if parts else "unknown"

    def save_report(self, report: BenchmarkReport, filename: str = "benchmark_report") -> Tuple[Path, Path]:
        """Save report as JSON and Markdown. Returns (json_path, md_path)."""
        json_path = self.output_dir / f"{filename}.json"
        md_path = self.output_dir / f"{filename}.md"

        # JSON report
        json_data = {
            "timestamp": report.timestamp,
            "summary": {
                "total": report.total_challenges,
                "successful": report.successful,
                "failed": report.failed,
                "errored": report.errored,
                "success_rate": round(report.success_rate, 3),
                "avg_rounds": round(report.avg_rounds, 1),
                "avg_elapsed_seconds": round(report.avg_elapsed_seconds, 1),
                "avg_token_estimate": round(report.avg_token_estimate, 0),
            },
            "category_stats": report.category_stats,
            "failure_reasons": report.failure_reasons,
            "top_routes": dict(
                sorted(report.top_routes.items(), key=lambda x: x[1], reverse=True)
            ),
            "runs": [
                {
                    "challenge": r.challenge,
                    "success": r.success,
                    "flag": r.flag,
                    "rounds": r.rounds,
                    "elapsed_seconds": round(r.elapsed_seconds, 1),
                    "token_estimate": r.token_estimate,
                    "routes_tried": r.routes_tried,
                    "winning_route": r.winning_route,
                    "completion_type": r.completion_type,
                    "llm_key_decisions": r.llm_key_decisions,
                    "helper_key_decisions": r.helper_key_decisions,
                    "failure_reason": r.failure_reason,
                    "error": r.error,
                }
                for r in report.runs
            ],
        }
        json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")

        # Markdown report
        md_lines = [
            "# Web CTF Benchmark Report",
            "",
            f"**Timestamp**: {report.timestamp}",
            f"**Model**: DeepSeek v4-pro (thinking={'on' if self.thinking else 'off'})",
            f"**Max iterations per challenge**: {self.max_iterations}",
            f"**Timeout per challenge**: {self.timeout_per_challenge}s",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Total challenges | {report.total_challenges} |",
            f"| Successful | {report.successful} |",
            f"| Failed | {report.failed} |",
            f"| Errored | {report.errored} |",
            f"| **Success rate** | **{report.success_rate:.1%}** |",
            f"| Avg rounds | {report.avg_rounds:.1f} |",
            f"| Avg elapsed | {report.avg_elapsed_seconds:.1f}s |",
            f"| Avg token estimate | {report.avg_token_estimate:.0f} |",
            "",
            "## Category Results",
            "",
            "| Category | Total | Success | Rate | Avg Rounds |",
            "|---|---|---|---|---|",
        ]

        for cat, stats in sorted(report.category_stats.items()):
            rate = stats["successful"] / max(stats["total"], 1)
            md_lines.append(
                f"| {cat} | {stats['total']} | {stats['successful']} | "
                f"{rate:.0%} | {stats['avg_rounds']:.1f} |"
            )

        md_lines.extend([
            "",
            "## Detailed Results",
            "",
            "| Challenge | Result | Rounds | Time | Route | Failure Reason |",
            "|---|---|---|---|---|---|",
        ])

        for r in report.runs:
            status = "✅" if r.success else ("❌" if r.error else "❌")
            reason = (r.failure_reason or "")[:80]
            md_lines.append(
                f"| {r.challenge} | {status} | {r.rounds} | "
                f"{r.elapsed_seconds:.0f}s | {r.winning_route} | {reason} |"
            )

        if report.failure_reasons:
            md_lines.extend([
                "",
                "## Failure Analysis",
                "",
                "| Reason | Count |",
                "|---|---|",
            ])
            for reason, count in sorted(report.failure_reasons.items(), key=lambda x: x[1], reverse=True):
                md_lines.append(f"| {reason} | {count} |")

        md_path.write_text("\n".join(md_lines), encoding="utf-8")
        return json_path, md_path
