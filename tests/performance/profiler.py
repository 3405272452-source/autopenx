"""Performance profiling for AutoPenX pipeline comparison."""
from __future__ import annotations

import time
import tracemalloc
import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PerformanceSnapshot:
    label: str
    wall_time_ms: int
    peak_memory_mb: float
    tool_invocations: int
    llm_calls: int
    findings_count: int
    phases_completed: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "wall_time_ms": self.wall_time_ms,
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "tool_invocations": self.tool_invocations,
            "llm_calls": self.llm_calls,
            "findings_count": self.findings_count,
            "phases_completed": self.phases_completed,
        }


@dataclass
class ComparisonResult:
    single_agent: PerformanceSnapshot
    multi_agent: PerformanceSnapshot
    speedup_ratio: float
    memory_overhead_pct: float

    def summary(self) -> str:
        return (
            f"Performance Comparison:\n"
            f"  Single-agent: {self.single_agent.wall_time_ms}ms, "
            f"{self.single_agent.peak_memory_mb}MB peak\n"
            f"  Multi-agent:  {self.multi_agent.wall_time_ms}ms, "
            f"{self.multi_agent.peak_memory_mb}MB peak\n"
            f"  Speedup: {self.speedup_ratio:.2f}x\n"
            f"  Memory overhead: {self.memory_overhead_pct:.1f}%"
        )


class PipelineProfiler:
    """Profile AutoPenX pipeline execution."""

    def profile_run(
        self,
        target: str,
        multi_agent: bool = False,
        mock: bool = True,
    ) -> PerformanceSnapshot:
        """Run a full pipeline and measure performance.

        When *mock* is True the orchestrator uses the rule-based MockBrain,
        avoiding any LLM or network dependency.
        """
        from autopnex.orchestrator import LLMOrchestrator
        from autopnex.state_machine.machine import PenTestStateMachine

        orchestrator = LLMOrchestrator(mock=mock)

        tracemalloc.start()
        start = time.perf_counter()

        fsm = PenTestStateMachine(
            target=target,
            orchestrator=orchestrator,
            multi_agent=multi_agent,
        )
        findings = fsm.run()

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        completed_phases = sum(
            1 for phase in ("RECON", "SCAN", "VULN_DETECT", "EXPLOIT", "REPORT")
            if any(
                entry.get("state") == phase and "Entering" in entry.get("message", "")
                for entry in findings.state_log
            )
        )

        label = "multi_agent" if multi_agent else "single_agent"
        return PerformanceSnapshot(
            label=label,
            wall_time_ms=elapsed_ms,
            peak_memory_mb=peak_bytes / (1024 * 1024),
            tool_invocations=len(findings.tool_invocations),
            llm_calls=0 if mock else len(findings.tool_invocations),
            findings_count=len(findings.findings),
            phases_completed=completed_phases,
        )

    def compare(self, target: str, runs: int = 3) -> ComparisonResult:
        """Compare single-agent vs multi-agent performance over *runs* iterations.

        Returns the comparison based on median wall-time across runs.
        """
        single_snapshots: List[PerformanceSnapshot] = []
        multi_snapshots: List[PerformanceSnapshot] = []

        for _ in range(runs):
            single_snapshots.append(self.profile_run(target, multi_agent=False))
            multi_snapshots.append(self.profile_run(target, multi_agent=True))

        single_times = [s.wall_time_ms for s in single_snapshots]
        multi_times = [s.wall_time_ms for s in multi_snapshots]

        median_single_idx = single_times.index(
            sorted(single_times)[len(single_times) // 2]
        )
        median_multi_idx = multi_times.index(
            sorted(multi_times)[len(multi_times) // 2]
        )

        single = single_snapshots[median_single_idx]
        multi = multi_snapshots[median_multi_idx]

        speedup = single.wall_time_ms / multi.wall_time_ms if multi.wall_time_ms else float("inf")
        mem_overhead = (
            ((multi.peak_memory_mb - single.peak_memory_mb) / single.peak_memory_mb * 100)
            if single.peak_memory_mb > 0
            else 0.0
        )

        return ComparisonResult(
            single_agent=single,
            multi_agent=multi,
            speedup_ratio=round(speedup, 2),
            memory_overhead_pct=round(mem_overhead, 1),
        )
