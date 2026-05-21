"""Scan specialist — parallel for discovery tools, sequential for crawl."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import List

from ..state_machine.findings import TaskItem
from .base import AgentResult, AgentStatus, BaseAgent, register_agent

log = logging.getLogger("autopnex.agents.scan")

_SEQUENTIAL_TOOLS = {"crawl"}


@register_agent
class ScanAgent(BaseAgent):
    name = "ScanAgent"
    tool_categories = ["scan"]

    async def execute(self, tasks: List[TaskItem]) -> AgentResult:
        self.status = AgentStatus.RUNNING
        self._emit("phase_start", phase="SCAN", task_count=len(tasks))
        start = time.perf_counter_ns()
        completed = 0
        failed = 0

        parallel_tasks = [t for t in tasks if t.tool not in _SEQUENTIAL_TOOLS]
        sequential_tasks = [t for t in tasks if t.tool in _SEQUENTIAL_TOOLS]

        # Phase 1: run discovery tools in parallel
        if parallel_tasks:
            results = await asyncio.gather(
                *[self._run_task(t) for t in parallel_tasks],
                return_exceptions=True,
            )
            for task, result in zip(parallel_tasks, results):
                if isinstance(result, BaseException):
                    failed += 1
                    log.warning("ScanAgent task %s raised: %s", task.ref, result)
                    self._emit("task_error", task_ref=task.ref, error=str(result))
                    continue
                if result.success:
                    completed += 1
                else:
                    failed += 1
                self._ingest_result("SCAN", task, result)
                self._emit("task_done", task_ref=task.ref, success=result.success, summary=result.summary)

        # Phase 2: run crawl sequentially (depends on discovered paths)
        for task in sequential_tasks:
            try:
                result = await self._run_task(task)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                log.warning("ScanAgent task %s raised: %s", task.ref, exc)
                self._emit("task_error", task_ref=task.ref, error=str(exc))
                continue
            if result.success:
                completed += 1
            else:
                failed += 1
            self._ingest_result("SCAN", task, result)
            self._emit("task_done", task_ref=task.ref, success=result.success, summary=result.summary)

        self.status = AgentStatus.DONE
        self._emit("phase_done", phase="SCAN", completed=completed, failed=failed)
        return self._timed_result(start, completed=completed, failed=failed)
