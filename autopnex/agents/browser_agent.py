"""Browser specialist — runs Playwright-based browser automation tests."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import List

from ..state_machine.findings import TaskItem
from .base import AgentResult, AgentStatus, BaseAgent, register_agent

log = logging.getLogger("autopnex.agents.browser")


@register_agent
class BrowserAgent(BaseAgent):
    name = "BrowserAgent"
    tool_categories = ["browser"]

    async def execute(self, tasks: List[TaskItem]) -> AgentResult:
        self.status = AgentStatus.RUNNING
        self._emit("phase_start", phase="BROWSER", task_count=len(tasks))
        start = time.perf_counter_ns()
        completed = 0
        failed = 0

        results = await asyncio.gather(
            *[self._run_task(t) for t in tasks],
            return_exceptions=True,
        )

        for task, result in zip(tasks, results):
            if isinstance(result, BaseException):
                failed += 1
                log.warning("BrowserAgent task %s raised: %s", task.ref, result)
                self._emit("task_error", task_ref=task.ref, error=str(result))
                continue
            if result.success:
                completed += 1
            else:
                failed += 1
            self._ingest_result("EXPLOIT", task, result)
            self._emit(
                "task_done",
                task_ref=task.ref,
                success=result.success,
                summary=result.summary,
            )

        self.status = AgentStatus.DONE
        self._emit("phase_done", phase="BROWSER", completed=completed, failed=failed)
        return self._timed_result(start, completed=completed, failed=failed)
