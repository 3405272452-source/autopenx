"""ReAct-style LLM orchestrator coordinating tool calls per state-machine iteration."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from config.settings import RuntimeConfig
from ..tools.base import ToolRegistry
from .llm_client import LLMClient, LLMError
from .mock_brain import MockBrain
from .prompts import SYSTEM_PROMPT, build_user_prompt


STATE_TOOL_CATEGORIES = {
    "RECON": ["recon", "docker"],
    "SCAN": ["scan"],
    "VULN_DETECT": ["vuln", "ctf_web", "docker"],
    "EXPLOIT": ["exploit", "ctf_web", "browser", "docker"],
    "REPORT": [],
}


@dataclass
class ReActStep:
    state: str
    iteration: int
    tool: Optional[str] = None
    task_ref: Optional[str] = None
    arguments: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    action: str = "stay"  # stay | advance | done
    reason: str = ""
    decision_error: Optional[str] = None
    tool_success: Optional[bool] = None
    tool_summary: str = ""
    tool_duration_ms: int = 0
    tool_error: Optional[str] = None
    raw_output_excerpt: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)


class LLMOrchestrator:
    def __init__(
        self,
        *,
        mock: bool = False,
        client: Optional[LLMClient] = None,
        runtime_config: Optional[RuntimeConfig] = None,
    ):
        self.client = client or LLMClient()
        self.mock_forced = mock
        self.runtime_config = runtime_config
        self._mock_brain = MockBrain()
        self._event_cb: Callable[[Dict[str, Any]], None] = lambda _e: None
        self._degraded = False
        self._history: List[Dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        self._rejected_calls: set = set()
        self._consecutive_rejections: int = 0

    # ------------------------------------------------------------------
    @property
    def mode(self) -> str:
        if self.mock_forced or not self.client.enabled:
            return "mock"
        if self._degraded:
            return "llm_degraded"
        return "llm"

    # ------------------------------------------------------------------
    def reset_for_state(self, state: str) -> None:
        self._history = [{"role": "system", "content": SYSTEM_PROMPT}]
        self._rejected_calls.clear()
        self._consecutive_rejections = 0

    def set_event_callback(self, callback: Optional[Callable[[Dict[str, Any]], None]]) -> None:
        self._event_cb = callback or (lambda _e: None)

    def _emit(self, event: str, **payload: Any) -> None:
        try:
            self._event_cb({"event": event, **payload})
        except Exception:  # noqa: BLE001
            pass

    def step(self, state: str, findings_snapshot: Dict[str, Any], iteration: int, max_iter: int) -> ReActStep:
        user_prompt = build_user_prompt(state, findings_snapshot, iteration, max_iter)
        self._history.append({"role": "user", "content": user_prompt})
        tools_schema = ToolRegistry.openai_schemas(
            categories=STATE_TOOL_CATEGORIES.get(state, []),
            runtime_config=self.runtime_config,
        )
        phase_tasks = findings_snapshot.get("phase_tasks") or []

        if self.mode == "mock":
            assistant_msg = self._mock_brain.decide(state, findings_snapshot)
        else:
            try:
                assistant_msg = self.client.chat(self._history, tools=tools_schema or None)
            except LLMError as exc:
                self._degraded = True
                self._emit("llm_degraded", error=str(exc), state=state, iteration=iteration)
                assistant_msg = self._mock_brain.decide(state, findings_snapshot)
                assistant_msg["content"] = f"[llm_degraded] {exc}\n" + (assistant_msg.get("content") or "")

        history_entry: Dict[str, Any] = {
            "role": "assistant",
            "content": assistant_msg.get("content", ""),
            "tool_calls": assistant_msg.get("tool_calls") or None,
        }
        if assistant_msg.get("reasoning_content"):
            history_entry["reasoning_content"] = assistant_msg["reasoning_content"]
        self._history.append(history_entry)

        self._emit(
            "llm_response",
            state=state,
            iteration=iteration,
            content=(assistant_msg.get("content") or "")[:2000],
            reasoning_content=(assistant_msg.get("reasoning_content") or "")[:2000],
            tool_calls=[
                {"name": tc.get("function", {}).get("name", ""), "arguments": tc.get("function", {}).get("arguments", "")}
                for tc in (assistant_msg.get("tool_calls") or [])
            ],
            usage=assistant_msg.get("usage") or {},
        )

        tool_calls = assistant_msg.get("tool_calls") or []
        step = ReActStep(
            state=state,
            iteration=iteration,
            reasoning=(assistant_msg.get("content") or "")[:400],
        )
        if tool_calls:
            call = tool_calls[0]
            func = call.get("function", {})
            name = func.get("name")
            try:
                args = json.loads(func.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            matched_task = self._match_phase_task(phase_tasks, name, args)
            if phase_tasks and matched_task is None:
                step.tool = None
                call_key = f"{name}|{json.dumps(args, sort_keys=True)}"
                self._rejected_calls.add(call_key)
                step.decision_error = "decision_rejected:not_in_phase_task_list"
                self._emit(
                    "decision_rejected",
                    state=state,
                    iteration=iteration,
                    tool=name,
                    arguments=args,
                    reason=step.decision_error,
                )
                # Build a helpful rejection message listing pending tasks
                pending_tasks = [t for t in phase_tasks if t.get("status") == "todo"]
                pending_summary = "; ".join(
                    f"{t.get('tool')}({json.dumps(t.get('arguments', {}), ensure_ascii=False)[:80]})"
                    for t in pending_tasks[:8]
                )
                reject_msg = (
                    f"Tool call rejected: '{name}' is not in the permitted phase task list. "
                    f"Pending tasks: [{pending_summary}]. "
                    f"Call one of these tasks or return JSON: {{\"action\": \"advance\", \"reason\": \"...\"}}"
                )
                for tc in tool_calls:
                    self._history.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.get("id"),
                            "name": tc.get("function", {}).get("name", ""),
                            "content": reject_msg,
                        }
                    )
                self._consecutive_rejections += 1
                all_done = all(t.get("status") != "todo" for t in phase_tasks)
                if all_done:
                    step.action = "advance"
                    step.reason = "all phase tasks completed, auto-advancing"
                    return step
                # Auto-advance after 3 consecutive rejections to avoid infinite loops
                if self._consecutive_rejections >= 3:
                    step.action = "advance"
                    step.reason = f"auto-advancing after {self._consecutive_rejections} consecutive rejections"
                    self._consecutive_rejections = 0
                    return step
                content = (assistant_msg.get("content") or "").strip()
                action, reason = _parse_directive(content)
                if action in ("advance", "done"):
                    step.action = action
                    step.reason = reason
                else:
                    step.action = "stay"
                    step.reason = "tool not permitted for this phase task list"
                return step
            step.tool = name
            step.task_ref = matched_task.get("ref") if matched_task else None
            step.arguments = args
            step.action = "stay"
            self._consecutive_rejections = 0  # reset on successful tool match
            self._emit("tool_start", state=state, iteration=iteration, tool=name, arguments=args)
            result = ToolRegistry.execute(name, args, runtime_config=self.runtime_config)
            step.tool_success = result.success
            step.tool_summary = result.summary
            step.tool_duration_ms = result.duration_ms
            step.tool_error = result.error
            step.raw_output_excerpt = (result.raw_output or "")[:800]
            step.parsed_data = result.parsed_data or {}
            self._emit(
                "tool_finish",
                state=state,
                iteration=iteration,
                tool=name,
                arguments=args,
                success=result.success,
                summary=result.summary,
                duration_ms=result.duration_ms,
                error=result.error,
                raw_output_excerpt=step.raw_output_excerpt,
                parsed_data=step.parsed_data,
            )
            if not result.success:
                self._emit(
                    "tool_error",
                    state=state,
                    iteration=iteration,
                    tool=name,
                    arguments=args,
                    error=result.error,
                    summary=result.summary,
                )
            self._history.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id"),
                    "name": name,
                    "content": result.to_llm_message(),
                }
            )
            for extra_tc in tool_calls[1:]:
                self._history.append(
                    {
                        "role": "tool",
                        "tool_call_id": extra_tc.get("id"),
                        "name": extra_tc.get("function", {}).get("name", ""),
                        "content": "Only the first tool call is processed per turn.",
                    }
                )
            step._tool_result = result  # type: ignore[attr-defined]
            return step

        # No tool call — look for an action directive in content.
        content = (assistant_msg.get("content") or "").strip()
        action, reason = _parse_directive(content)
        step.action = action
        step.reason = reason
        return step

    def _match_phase_task(self, phase_tasks: List[Dict[str, Any]], tool: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # First: exact match on tool + arguments
        for task in phase_tasks:
            if task.get("status") != "todo":
                continue
            if task.get("tool") != tool:
                continue
            task_args = task.get("arguments") or {}
            if all(arguments.get(key) == value for key, value in task_args.items()):
                return task
        # Second: match by tool name only (accept any pending task for this tool)
        for task in phase_tasks:
            if task.get("status") != "todo":
                continue
            if task.get("tool") == tool:
                return task
        return None


def _parse_directive(content: str) -> tuple[str, str]:
    if not content:
        return "stay", "empty_response"
    # Attempt JSON parsing first
    try:
        # Trim code fences if any
        c = content.strip()
        if c.startswith("```"):
            c = c.split("```", 2)[1] if "```" in c[3:] else c.strip("`")
            if c.lower().startswith("json"):
                c = c[4:].lstrip()
        data = json.loads(c)
        if isinstance(data, dict) and "action" in data:
            action = str(data.get("action") or "advance").lower()
            if action not in ("stay", "advance", "done"):
                action = "advance"
            return action, str(data.get("reason") or "")
    except Exception:  # noqa: BLE001
        pass
    return "stay", "invalid_decision_format"
