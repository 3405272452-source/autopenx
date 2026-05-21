"""Base agent class and agent registry for the multi-agent architecture."""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type

from config.settings import RuntimeConfig
from ..tools.base import ToolRegistry, ToolResult
from ..state_machine.findings import TaskItem
from ..state_machine.ingester import ingest_tool_result
from .blackboard import Blackboard

log = logging.getLogger("autopnex.agents")


class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class AgentResult:
    agent_name: str
    status: AgentStatus
    tasks_completed: int = 0
    tasks_failed: int = 0
    duration_ms: int = 0
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Agent registry
# ---------------------------------------------------------------------------

_AGENT_REGISTRY: Dict[str, Type["BaseAgent"]] = {}


def register_agent(cls: Type["BaseAgent"]) -> Type["BaseAgent"]:
    """Class decorator that registers a specialist agent by its *name*."""
    _AGENT_REGISTRY[cls.name] = cls
    return cls


def get_agent_class(name: str) -> Optional[Type["BaseAgent"]]:
    return _AGENT_REGISTRY.get(name)


def all_agent_classes() -> Dict[str, Type["BaseAgent"]]:
    return dict(_AGENT_REGISTRY)


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    """Abstract specialist agent.

    Subclasses must set the class attributes *name* and *tool_categories*
    and implement :meth:`execute`.
    """

    name: str = ""
    tool_categories: List[str] = []

    def __init__(
        self,
        blackboard: Blackboard,
        config: RuntimeConfig,
        *,
        llm_client: Any = None,
        max_concurrent: int = 4,
    ) -> None:
        self.blackboard = blackboard
        self.config = config
        self.llm_client = llm_client
        self.status = AgentStatus.IDLE
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._event_callbacks: List[Callable[..., Any]] = []

    # -- abstract -----------------------------------------------------------

    @abstractmethod
    async def execute(self, tasks: List[TaskItem]) -> AgentResult:
        """Run all *tasks* and return a summary result."""

    # -- tool execution -----------------------------------------------------

    async def _run_task(self, task: TaskItem) -> ToolResult:
        """Execute a single tool invocation under the concurrency semaphore."""
        async with self._semaphore:
            return await asyncio.to_thread(
                ToolRegistry.execute, task.tool, task.arguments, self.config,
            )

    # -- result ingestion ---------------------------------------------------

    def _ingest_result(self, phase: str, task: TaskItem, result: ToolResult) -> None:
        """Write a tool result into the shared blackboard."""
        def _mutate(findings):
            ingest_tool_result(
                findings,
                phase=phase,
                tool=task.tool,
                arguments=task.arguments,
                result=result,
            )
            findings.record_invocation(
                phase, task.tool, task.arguments, result, task_ref=task.ref,
            )
            findings.mark_task(phase, task.ref, "done", result.summary)
            findings.add_artifact(
                parent_ref=task.ref,
                phase=phase,
                tool=task.tool,
                kind="tool_result",
                summary=result.summary,
                raw_output_excerpt=result.raw_output,
                metadata={"arguments": task.arguments, "success": result.success},
            )

        self.blackboard.write(_mutate)

    # -- events -------------------------------------------------------------

    def on_event(self, callback: Callable[..., Any]) -> None:
        self._event_callbacks.append(callback)

    def _emit(self, event: str, **payload: Any) -> None:
        payload.setdefault("agent", self.name)
        for cb in self._event_callbacks:
            try:
                cb(event, **payload)
            except Exception:  # noqa: BLE001
                log.debug("agent event callback error", exc_info=True)

    # -- helpers ------------------------------------------------------------

    def _timed_result(
        self,
        start_ns: int,
        *,
        completed: int,
        failed: int,
        error: Optional[str] = None,
    ) -> AgentResult:
        elapsed = int((time.perf_counter_ns() - start_ns) / 1_000_000)
        status = AgentStatus.DONE if error is None else AgentStatus.FAILED
        return AgentResult(
            agent_name=self.name,
            status=status,
            tasks_completed=completed,
            tasks_failed=failed,
            duration_ms=elapsed,
            error=error,
        )
