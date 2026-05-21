"""Vulnerability detection specialist — parallel with priority-based scheduling."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import List

from ..state_machine.findings import TaskItem
from .base import AgentResult, AgentStatus, BaseAgent, register_agent

log = logging.getLogger("autopnex.agents.vuln")


@register_agent
class VulnDetectAgent(BaseAgent):
    name = "VulnDetectAgent"
    tool_categories = ["vuln"]

    async def execute(self, tasks: List[TaskItem]) -> AgentResult:
        self.status = AgentStatus.RUNNING
        self._emit("phase_start", phase="VULN_DETECT", task_count=len(tasks))
        start = time.perf_counter_ns()
        completed = 0
        failed = 0

        sorted_tasks = sorted(tasks, key=lambda t: t.priority_score, reverse=True)

        batch_size = self._semaphore._value  # noqa: SLF001
        for offset in range(0, len(sorted_tasks), batch_size):
            batch = sorted_tasks[offset : offset + batch_size]
            results = await asyncio.gather(
                *[self._run_task(t) for t in batch],
                return_exceptions=True,
            )
            for task, result in zip(batch, results):
                if isinstance(result, BaseException):
                    failed += 1
                    log.warning("VulnDetectAgent task %s raised: %s", task.ref, result)
                    self._emit("task_error", task_ref=task.ref, error=str(result))
                    continue
                if result.success:
                    completed += 1
                else:
                    failed += 1
                self._ingest_result("VULN_DETECT", task, result)
                self._emit(
                    "task_done",
                    task_ref=task.ref,
                    success=result.success,
                    summary=result.summary,
                )

        self.status = AgentStatus.DONE
        self._emit("phase_done", phase="VULN_DETECT", completed=completed, failed=failed)
        return self._timed_result(start, completed=completed, failed=failed)
