"""CTF ReAct Agent - LLM-driven tool calling loop for automated CTF solving.

Uses DeepSeek v4-pro with thinking mode and function calling to drive a
ReAct (Reasoning + Acting) loop. The LLM decides which tool to call,
the agent executes it, feeds the observation back, and repeats until
a flag is found or limits are reached.
"""
from __future__ import annotations

import json
import logging
import re
import time
import warnings
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import requests

from config.settings import RuntimeConfig, settings
from .capability_registry import CTFCapabilityRegistry
from .tool_router import (
    CORE_TOOL_NAMES,
    ToolRouter,
)
from .diagnostics import (
    check_flag_in_text as _check_flag_in_text_value,
    compact_for_llm as _compact_for_llm_value,
    diagnose_tool_result as _diagnose_tool_result_value,
    extract_blockers as _extract_blockers_value,
    extract_crypto_hints as _extract_crypto_hints_value,
    extract_lessons as _extract_lessons_value,
    normalise_flag_format as _normalise_flag_format_value,
)
from .action_runtime import ActionRuntime
from .agent_pool import AgentPool
from .artifact_store import ArtifactStore
from .consensus import Consensus
from .critic import AICritic, Critic
from .environment_probe import EnvironmentProbe
from .flag_engine import FlagEngine
from .fuse_controller import FuseController
from .helpers.dispatcher import DeterministicHelperDispatcher
from .shared_journal import AttemptRecord, EvidenceCard, SharedJournal
from .task_queue import TaskQueue
from .web_session import SessionFlowManager
from .models import ChallengeProfile, ChallengeType
from .prompt_compiler import PromptCompiler
from .route_cards import get_route_card
from .web_state_blackboard import WebStateBlackboard
from .session import CTFSessionState
from .workers import (
    BaseCTFWorker,
    ReconWorker,
    ReverseCryptoWorker,
    WebExploitWorker,
    WorkerContext,
)
from .source_analyzer import SourceAnalysis, analyze_attachment
from .strategy import StrategyEngine
from .tool_workspace import CTFToolWorkspace
from .. import tools as _tools  # noqa: F401  (load ToolRegistry entries)
from ..tools.base import ToolRegistry

log = logging.getLogger("autopnex.ctf.react_agent")



# ---------------------------------------------------------------------------
# CTFReActAgent
# ---------------------------------------------------------------------------


class CTFReActAgent:
    """Agent that uses DeepSeek function calling to solve CTF challenges.

    Implements a ReAct loop: the LLM reasons about the challenge, decides
    which tool to call, the agent executes it, feeds the result back, and
    repeats until a flag is found or limits are reached.
    """

    def __init__(
        self,
        target: str,
        challenge_type: Optional[str] = None,
        flag_format: str = r"flag\{[^}]+\}",
        max_iterations: int = 15,
        timeout: int = 300,
        thinking: bool = True,
        enabled_tools: Optional[List[str]] = None,
        runtime_config: Optional[RuntimeConfig] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        knowledge_base_path: Optional[str] = None,
        multi_agent: bool = False,
    ):
        self.target = target
        self.challenge_type = challenge_type
        self.flag_format = _normalise_flag_format_value(flag_format)
        self.max_iterations = max_iterations
        self.timeout = timeout
        self.thinking = thinking
        self.runtime_config = runtime_config or settings.snapshot()
        self.multi_agent = multi_agent or getattr(self.runtime_config, 'multi_agent_enabled', False)
        self.enabled_tools: Set[str] = self._normalise_enabled_tools(enabled_tools)
        self._progress_cb = progress_callback or (lambda _event: None)

        # Internal state
        self._state = CTFSessionState(
            target=target,
            challenge_type=challenge_type,
            flag_format=self.flag_format,
        )
        self._files: List[str] = self._state.files
        self._source_analyses: List[SourceAnalysis] = []
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "AutoPenX-CTF/1.0"})
        self._tool_workspace = CTFToolWorkspace(self.runtime_config.ctf_workspace_dir)
        self._flag_engine = FlagEngine(flag_formats=[self.flag_format])
        self._steps: List[Dict[str, Any]] = self._state.steps
        self._messages: List[Dict[str, Any]] = self._state.messages
        self._llm: Optional[Any] = None
        self._helper_dispatcher = DeterministicHelperDispatcher()
        self._capability = CTFCapabilityRegistry(self._helper_dispatcher).resolve(self.challenge_type, self.target)

        # Knowledge base integration
        from .knowledge_base import CTFKnowledgeBase
        kb_path = knowledge_base_path or str(Path(__file__).parent.parent.parent / "ctf_knowledge.json")
        self._kb = CTFKnowledgeBase(storage_path=Path(kb_path))

        # Tool router
        self._tool_router = ToolRouter(
            runtime_config=self.runtime_config,
            flag_engine=self._flag_engine,
            tool_workspace=self._tool_workspace,
            knowledge_base=self._kb,
            session=self._session,
            challenge_type=self.challenge_type,
            enabled_tools=self.enabled_tools,
        )

        # Environment probe
        self._env_probe = EnvironmentProbe(runtime_config=self.runtime_config)
        self._probe_result = self._env_probe.probe()

        # Artifact store
        self._artifact_store = ArtifactStore(
            workspace_dir=self.runtime_config.ctf_workspace_dir or str(self._tool_workspace.root)
        )

        # Action runtime (wraps tool_router with retry/classify)
        self._action_runtime = ActionRuntime(
            tool_router=self._tool_router,
            max_retries=2,
            base_timeout=30.0,
        )

        # Web session flow manager (forms, login, CSRF)
        self._flow_manager = SessionFlowManager(session=self._session)

        # Strategy engine (budget, dedup, route switching)
        self._strategy = StrategyEngine(
            max_total_cost=50,
            max_iterations=self.max_iterations,
            helper_budget_per_route=3,
        )

        # Shared journal (structured session logs)
        session_id = f"{int(time.time())}"
        session_dir = Path(self.runtime_config.ctf_workspace_dir or str(self._tool_workspace.root)) / "sessions" / session_id
        self._journal = SharedJournal(str(session_dir), session_id=session_id)

        # Fuse controller (circuit breaker)
        self._fuse = FuseController(
            repeat_threshold=2,
            no_evidence_rounds=4,
            error_repeat_limit=3,
            idle_rounds_limit=3,
        )

        # Critic / Verifier (read-only review)
        self._critic = Critic()
        self._ai_critic = AICritic()
        self._last_critic_iteration = 0

        # Last action result for fuse tracking
        self._last_action_result: Optional[Any] = None

        # Prompt compiler (replaces monolithic _build_initial_messages)
        self._compiler = PromptCompiler()
        # Web state blackboard (structured state instead of message-history state)
        self._blackboard = WebStateBlackboard(target_url=target)
        # Current route detection
        self._current_route: str = "recon"

        # Emit profile ready event with probe results
        self._emit(
            "ctf_profile_ready",
            challenge_type=self.challenge_type,
            probe=self._probe_result.to_dict(),
            missing=self._probe_result.missing,
            warnings=self._probe_result.warnings,
        )

        # Multi-agent infrastructure (Phase 5)
        self._task_queue = TaskQueue()
        self._agent_pool = AgentPool(
            task_queue=self._task_queue,
            max_llm_workers=2,
            max_tool_workers=5,
        )
        self._consensus = Consensus(
            task_queue=self._task_queue,
            shared_journal=self._journal,
        )
        # Register coordinator role for this agent instance
        self._coordinator_id = self._agent_pool.register(role="coordinator")
        # Pre-register other roles for future worker expansion
        self._recon_worker_id = self._agent_pool.register(role="recon")
        self._exploit_worker_id = self._agent_pool.register(role="exploit")
        self._support_worker_id = self._agent_pool.register(role="support")
        self._critic_worker_id = self._agent_pool.register(role="critic")

        # Phase 6: start real background workers
        self._worker_ctx = WorkerContext(
            target=self.target,
            session=self._session,
            tool_router=self._tool_router,
            journal=self._journal,
            strategy=self._strategy,
            flag_engine=self._flag_engine,
            runtime_config=self.runtime_config,
            critic=self._critic,
            fuse=self._fuse,
        )
        self._worker_threads: List[BaseCTFWorker] = [
            ReconWorker(
                self._recon_worker_id, "recon", self._agent_pool,
                self._task_queue, self._worker_ctx,
            ),
            WebExploitWorker(
                self._exploit_worker_id, "exploit", self._agent_pool,
                self._task_queue, self._worker_ctx,
            ),
            ReverseCryptoWorker(
                self._support_worker_id, "support", self._agent_pool,
                self._task_queue, self._worker_ctx,
            ),
        ]
        for w in self._worker_threads:
            w.start()

    def add_file(self, file_path: str) -> None:
        """Add a challenge file for analysis."""
        if file_path and Path(file_path).exists():
            self._files.append(file_path)
            self._source_analyses.append(analyze_attachment(file_path))

    def _emit(self, event: str, **payload: Any) -> None:
        try:
            self._progress_cb({"event": event, **payload})
        except Exception:  # noqa: BLE001
            pass

    async def solve(self) -> Dict[str, Any]:
        """Main ReAct loop. Returns {success, flag, reasoning, steps, duration_ms}.

        When multi_agent=True, delegates to MultiAgentOrchestrator instead of
        running the standard ReAct loop.
        """
        start_time = time.time()

        # Multi-agent mode: delegate to rule-based collaboration
        if self.multi_agent:
            return await self._solve_multi_agent(start_time)

        # Initialize LLM client
        from ..orchestrator.llm_client import LLMClient, LLMError
        try:
            self._llm = LLMClient()
            if not self._llm.enabled:
                return self._result(False, error="LLM not configured (no API key)")
        except Exception as e:
            return self._result(False, error=f"Failed to initialize LLM: {e}")

        # Build initial messages
        self._messages.clear()
        self._messages.extend(self._build_initial_messages())
        self._emit(
            "ctf_start",
            target=self.target,
            challenge_type=self.challenge_type,
            enabled_tools=sorted(self.enabled_tools),
            files=list(self._files),
        )
        self._capability.run_preflight(self)
        self._emit(
            "ctf_preflight",
            capability=getattr(self._capability, "name", None) if self._capability else None,
        )
        self._journal.log_timeline(
            f"开始解题: target={self.target}, type={self.challenge_type}"
        )

        # ReAct loop
        iteration = 0

        while iteration < self.max_iterations:
            elapsed = time.time() - start_time
            if elapsed > self.timeout:
                log.warning("ReAct loop timed out after %.1fs", elapsed)
                break

            iteration += 1
            log.info("ReAct iteration %d/%d", iteration, self.max_iterations)
            self._emit("ctf_iteration_start", iteration=iteration, max_iterations=self.max_iterations)

            # Phase 6: submit initial background tasks once
            if iteration == 1:
                self._task_queue.submit(
                    kind="recon",
                    route="initial_probe",
                    payload={"url": self.target, "method": "GET"},
                    priority=10,
                )
                for f in self._files:
                    self._task_queue.submit(
                        kind="support",
                        route="file_analysis",
                        payload={"file_path": f},
                        priority=5,
                    )

            # Call LLM with tools + thinking
            try:
                response = self._call_llm()
            except LLMError as e:
                log.error("LLM call failed: %s", e)
                self._steps.append({"iteration": iteration, "error": str(e)})
                break
            except Exception as e:
                error_str = str(e)
                log.error("Unexpected LLM error: %s", e)
                # Retry once after fixing message history for tool_calls format errors
                if "tool_calls" in error_str and "tool messages" in error_str:
                    log.info("Attempting to fix message history for tool_calls format issue")
                    self._fix_message_history()
                    try:
                        response = self._call_llm()
                    except Exception as e2:
                        log.error("Retry also failed: %s", e2)
                        self._steps.append({"iteration": iteration, "error": str(e2)})
                        break
                else:
                    self._steps.append({"iteration": iteration, "error": error_str})
                    break

            # Capture reasoning
            reasoning = response.get("reasoning_content", "")
            if reasoning:
                self._state.add_reasoning(reasoning)

            content = response.get("content", "")
            tool_calls = response.get("tool_calls", [])
            self._emit(
                "ctf_llm_response",
                iteration=iteration,
                content=content[:4000],
                reasoning_content=reasoning[:8000],
                tool_calls=[
                    {"name": tc.get("function", {}).get("name", ""), "arguments": tc.get("function", {}).get("arguments", "")}
                    for tc in tool_calls
                ],
            )

            # Build assistant message for conversation history
            assistant_msg: Dict[str, Any] = {"role": "assistant"}
            # DeepSeek requires content to be None (not "") when tool_calls are present
            if content:
                assistant_msg["content"] = content
            else:
                assistant_msg["content"] = None
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            # Pass reasoning_content back (required by DeepSeek API for tool call turns)
            if reasoning:
                assistant_msg["reasoning_content"] = reasoning
            self._messages.append(assistant_msg)

            # Check if flag found in content
            if content:
                flag = self._check_flag_in_text(content)
                if flag:
                    duration_ms = int((time.time() - start_time) * 1000)
                    result = self._result(True, flag=flag, duration_ms=duration_ms)
                    self._record_attempt(result)
                    self._emit("ctf_done", **result)
                    self._stop_workers()
                    return result

            # If tool_calls: execute each and feed results back
            if tool_calls:
                # Collect all tool results first, then append diagnosis messages after
                # (DeepSeek API requires all tool responses immediately after the assistant message)
                pending_diagnoses: List[str] = []

                for tc in tool_calls:
                    tool_name = tc["function"]["name"]
                    tool_args_raw = tc["function"]["arguments"]
                    tool_call_id = tc["id"]

                    # Parse arguments
                    try:
                        tool_args = json.loads(tool_args_raw) if isinstance(tool_args_raw, str) else tool_args_raw
                    except json.JSONDecodeError:
                        tool_args = {}

                    # Execute tool
                    log.info("Executing tool: %s(%s)", tool_name, json.dumps(tool_args)[:200])
                    self._emit("ctf_tool_start", iteration=iteration, tool=tool_name, arguments=tool_args)
                    try:
                        tool_result = self._execute_tool(tool_name, tool_args)
                    except Exception as e:
                        log.error("Tool execution error: %s(%s) -> %s", tool_name, tool_args, e)
                        tool_result = {"error": f"{type(e).__name__}: {e}"}
                    self._emit(
                        "ctf_tool_finish",
                        iteration=iteration,
                        tool=tool_name,
                        arguments=tool_args,
                        result_preview=str(tool_result)[:2000],
                    )

                    # Update structured blackboard state from this tool result
                    self._update_blackboard(tool_name, tool_args, tool_result)

                    # Infer and set current route based on tool execution context
                    inferred_route = self._strategy.infer_route(tool_name, tool_args, tool_result)
                    if inferred_route != "unknown":
                        self._strategy.set_route(inferred_route)

                    # Log step
                    self._state.add_step(iteration, tool_name, tool_args, str(tool_result)[:500])

                    # Serialize result for the LLM
                    full_result_str = json.dumps(tool_result, ensure_ascii=False, default=str)
                    flag = self._check_flag_in_text(full_result_str)
                    result_str = _compact_for_llm_value(full_result_str)

                    # Append tool result message (MUST immediately follow assistant tool_calls)
                    self._messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call_id,
                        "content": result_str,
                    })

                    if flag:
                        duration_ms = int((time.time() - start_time) * 1000)
                        result = self._result(True, flag=flag, duration_ms=duration_ms)
                        self._record_attempt(result)
                        self._journal.log_timeline(f"找到 flag: {flag}")
                        self._emit("ctf_done", **result)
                        self._stop_workers()
                        return result

                    # Log attempt to shared journal
                    evidence = self._strategy.record_tool_result(tool_name, tool_args, tool_result)
                    route = self._strategy._current_route or "unknown"
                    self._journal.log_attempt(
                        AttemptRecord(
                            iteration=iteration,
                            tool=tool_name,
                            args_hash=self._strategy._hash_args(tool_name, tool_args),
                            route=route,
                            success=not bool(tool_result.get("error")),
                            result_preview=str(tool_result)[:200],
                            new_info=evidence.score > 0.1,
                        )
                    )

                    # Emit evidence card if score is notable
                    if evidence.score > 0.2:
                        card = EvidenceCard(
                            id=f"e{len(self._journal.evidence_cards)}",
                            source="tool_result",
                            agent="web",
                            route=route,
                            summary=f"{tool_name} 产生证据 (score={evidence.score:.2f})",
                            evidence=str(tool_result)[:300],
                            confidence=evidence.score,
                            next_action="继续当前路线或根据证据调整",
                        )
                        self._journal.log_evidence(card)
                        self._emit("ctf_evidence_card", **card.to_dict())

                    helper_result = self._run_deterministic_helpers(tool_name, tool_args, tool_result)
                    if helper_result:
                        self._emit(
                            "ctf_helper_triggered",
                            helper=helper_result.get("helper", "deterministic_helper"),
                            url=helper_result.get("url", self.target),
                        )
                        self._journal.log_timeline(
                            f"Helper 触发: {helper_result.get('helper', 'unknown')}"
                        )
                        helper_flag = self._check_flag_in_text(json.dumps(helper_result, ensure_ascii=False, default=str))
                        self._state.add_step(
                            iteration,
                            helper_result.get("helper", "deterministic_helper"),
                            {"url": helper_result.get("url", self.target)},
                            str(helper_result)[:500],
                        )
                        if helper_flag:
                            duration_ms = int((time.time() - start_time) * 1000)
                            result = self._result(True, flag=helper_flag, duration_ms=duration_ms)
                            self._record_attempt(result)
                            self._journal.log_timeline(f"Helper 找到 flag: {helper_flag}")
                            self._emit("ctf_done", **result)
                            self._stop_workers()
                            return result

                    diagnosis = _diagnose_tool_result_value(tool_name, tool_args, tool_result)
                    if diagnosis:
                        pending_diagnoses.append(diagnosis)

                # Now append diagnosis messages AFTER all tool responses are in place
                for diag in pending_diagnoses:
                    self._messages.append({
                        "role": "user",
                        "content": (
                            diag
                            + "\n基于该诊断调整下一步；不要无变化地重复同一请求或同一 payload。"
                        ),
                    })

                # Emit strategy state after all tools in this iteration
                self._emit("ctf_strategy_update", **self._strategy.get_summary())

                # Fuse check (use last tool_name/tool_args for repeat detection)
                last_tool_name = tool_calls[-1]["function"]["name"] if tool_calls else ""
                last_tool_args = tool_args if tool_calls else {}
                fuse_decision = self._fuse.check(
                    strategy=self._strategy,
                    journal=self._journal,
                    action_result=self._last_action_result,
                    iteration=iteration,
                    llm_content=content,
                    tool_calls_count=len(tool_calls),
                    tool_name=last_tool_name,
                    tool_args=last_tool_args,
                )
                if fuse_decision.level != "none":
                    self._fuse.apply_to_journal(fuse_decision, self._journal, self._strategy)
                    self._emit("ctf_fuse_triggered", **fuse_decision.to_dict())
                    if fuse_decision.level == "hard":
                        duration_ms = int((time.time() - start_time) * 1000)
                        result = self._result(
                            False,
                            duration_ms=duration_ms,
                            error=f"Hard fuse triggered: {fuse_decision.reason}",
                        )
                        self._record_attempt(result)
                        self._emit("ctf_done", **result)
                        return result
                    elif fuse_decision.level == "route":
                        self._emit("ctf_route_exhausted", route=fuse_decision.route_id, reason=fuse_decision.reason)
                        if fuse_decision.suggestion:
                            self._messages.append({
                                "role": "user",
                                "content": f"系统建议: {fuse_decision.suggestion}",
                            })

                # Critic review every 4 iterations or if stuck
                if iteration - self._last_critic_iteration >= 4 or (fuse_decision.level != "none" and fuse_decision.level != "soft"):
                    # When fuse detects stuck state, prioritize AICritic for "second opinion"
                    is_stuck_trigger = fuse_decision.level not in ("none", "soft")
                    if is_stuck_trigger:
                        review = await self._ai_critic.review(self._journal, self._strategy, self._fuse)
                    else:
                        review = self._critic.review(self._journal, self._strategy, self._fuse)
                    self._critic.write_to_journal(review, self._journal)
                    self._emit("ctf_next_action", **review.to_dict())
                    self._last_critic_iteration = iteration

                    # Inject AICritic recommendation into next LLM prompt
                    if review.recommended_next_action:
                        source_label = "AI Critic" if review.source == "ai" else "Critic"
                        self._messages.append({
                            "role": "user",
                            "content": (
                                f"[{source_label} 建议] {review.recommended_next_action}"
                            ),
                        })

                # If current route is exhausted, suggest switching
                route_switch = self._strategy.emit_if_route_exhausted()
                if route_switch:
                    self._emit("ctf_route_exhausted", route=route_switch["from"], reason="budget_exhausted")
                    self._messages.append({
                        "role": "user",
                        "content": (
                            f"路线 '{route_switch['from']}' 已用尽尝试预算仍未成功，"
                            f"建议切换到 '{route_switch['to']}' 或尝试其他攻击向量。"
                        ),
                    })

                # Multi-agent consensus ingestion (Phase 5)
                best_ev = self._strategy.get_summary().get("best_evidence") or {}
                self._consensus.ingest(
                    worker_id=self._coordinator_id,
                    role="coordinator",
                    task_id=f"iter-{iteration}",
                    result={
                        "iteration": iteration,
                        "route": self._strategy._current_route,
                        "strategy_summary": self._strategy.get_summary(),
                    },
                    evidence=list(self._journal.latest_evidence(3)),
                    confidence=best_ev.get("score", 0.0),
                )
                # Periodic consensus decision check (every 3 iterations)
                if iteration % 3 == 0:
                    decision = self._consensus.decide()
                    if decision.verdict in ("flag_found", "verified_flag") and decision.flag:
                        duration_ms = int((time.time() - start_time) * 1000)
                        result = self._result(True, flag=decision.flag, duration_ms=duration_ms)
                        self._record_attempt(result)
                        self._journal.log_timeline(f"Consensus 确认 flag: {decision.flag}")
                        self._emit("ctf_done", **result)
                        self._stop_workers()
                        return result
                    if decision.verdict == "route_suggestion" and decision.next_action:
                        self._messages.append({
                            "role": "user",
                            "content": f"多 Agent 共识建议: {decision.next_action}",
                        })
                    self._emit("ctf_consensus_decision", **decision.to_dict())

                # Phase 6: collect real worker results via consensus
                worker_flag = self._collect_worker_results(iteration)
                if worker_flag:
                    duration_ms = int((time.time() - start_time) * 1000)
                    result = self._result(True, flag=worker_flag, duration_ms=duration_ms)
                    self._record_attempt(result)
                    self._journal.log_timeline(f"Worker 发现 flag: {worker_flag}")
                    self._emit("ctf_done", **result)
                    self._stop_workers()
                    return result

                # Emit multi-agent status
                self._emit(
                    "ctf_multi_agent_status",
                    queue=self._task_queue.get_summary(),
                    pool=self._agent_pool.get_summary(),
                )

            elif not content:
                # No tool calls and no content - LLM might be stuck
                log.warning("LLM returned empty response at iteration %d", iteration)
                break

            # If LLM returned content but no tool calls and no flag,
            # it might be providing analysis. Continue the loop by prompting it.
            elif not tool_calls and content:
                # Check if LLM explicitly says it cannot find the flag
                lowered_content = content.lower()
                if iteration >= self.max_iterations and any(phrase in lowered_content for phrase in [
                    "无法找到", "cannot find", "unable to", "i give up",
                    "no flag found", "未能找到",
                ]):
                    break
                # Otherwise, nudge it to continue acting
                self._messages.append({
                    "role": "user",
                    "content": (
                        "Continue. Do not repeat source extraction if the static analysis already contains the needed facts. "
                        "Use the available tools to make concrete progress against the live target. "
                        "If you found the flag, output FLAG_FOUND: <flag_value>"
                    ),
                })

        # Loop ended without finding flag
        duration_ms = int((time.time() - start_time) * 1000)
        error_msg = "Max iterations reached without finding flag"
        if elapsed > self.timeout:
            error_msg = f"Timeout after {self.timeout}s without finding flag"
        result = self._result(False, duration_ms=duration_ms, error=error_msg)
        self._record_attempt(result)
        self._journal.log_timeline(f"解题结束: 未找到 flag ({error_msg})")
        self._emit("ctf_done", **result)
        self._stop_workers()
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_initial_messages(self) -> List[Dict[str, Any]]:
        """Build the initial system + user messages using PromptCompiler.

        Replaces the old monolithic prompt with the 4-layer structure:
        Core Prompt → Task Context → State Summary → RouteCard.
        """
        # Use PromptCompiler for the 4-layer structure
        messages = self._compiler.build_messages(
            target=self.target,
            flag_format=self.flag_format,
            challenge_type=self.challenge_type,
            max_iterations=self.max_iterations,
            timeout=self.timeout,
            blackboard=self._blackboard,
            route=self._current_route,
            files=list(self._files) if self._files else None,
        )

        # Append knowledge base context
        knowledge_context = self._build_knowledge_context()
        if knowledge_context:
            messages.append({"role": "user", "content": knowledge_context})

        # Append source analysis context
        source_context = self._build_source_context()
        if source_context:
            messages.append({"role": "user", "content": source_context})

        # Append skills context
        skills_context = self._build_skills_context()
        if skills_context:
            messages.append({"role": "user", "content": skills_context})

        # Check token budget
        in_budget, est, limit = self._compiler.check_budget(messages)
        if not in_budget:
            log.warning("Initial prompt exceeds token budget: %d/%d — compressing", est, limit)
            # Drop skills context first (largest, least critical)
            non_skill = [m for m in messages if "CTF Skills" not in str(m.get("content", ""))]
            messages = non_skill

        return messages

    def _build_knowledge_context(self) -> Optional[str]:
        """Build knowledge base context (compact)."""
        parts: List[str] = []
        knowledge_query = self._knowledge_query()
        if knowledge_query:
            hits = self._kb.search_knowledge(knowledge_query, challenge_type=self.challenge_type or "", limit=4)
            if hits:
                parts.append("## 知识库参考")
                parts.append("")
                for hit in hits:
                    name = hit.get("name") or hit.get("strategy_used") or hit.get("error") or hit.get("kind")
                    desc = hit.get("description") or "; ".join(hit.get("lessons", [])[:2]) or str(hit.get("blockers", ""))
                    parts.append(f"- [{hit.get('kind')}] {name}: {desc[:300]}")

        if self.challenge_type:
            from .models import ChallengeType
            try:
                ct = ChallengeType(self.challenge_type)
                similar = self._kb.query_similar(ct, tech_stack=[], limit=2)
                if similar:
                    if not parts:
                        parts.append("## 历史解题经验")
                        parts.append("")
                    else:
                        parts.append("")
                    for solve in similar:
                        parts.append(f"- {solve.get('target', '?')}: {solve.get('strategy_used', '?')}")
            except (ValueError, Exception):
                pass

        return "\n".join(parts) if parts else None

    def _build_source_context(self) -> Optional[str]:
        """Build source attachment analysis context."""
        if not self._source_analyses:
            return None
        parts = ["## 附件源码分析", ""]
        for analysis in self._source_analyses:
            parts.append(analysis.to_prompt_context())
            parts.append("")
        return "\n".join(parts)

    def _build_skills_context(self) -> Optional[str]:
        """Build CTF skills context (compact — max 5 items)."""
        skills_file = Path(__file__).parent / "data" / "ctf_skills.json"
        if not skills_file.exists():
            return None
        try:
            skills = json.loads(skills_file.read_text(encoding="utf-8"))
            relevant = skills.get(f"{self.challenge_type}_skills", []) + skills.get("general_tips", [])
            if not relevant:
                return None
            parts = ["## 相关技巧"]
            for skill in relevant[:5]:
                parts.append(f"- {skill}")
            return "\n".join(parts)
        except (json.JSONDecodeError, OSError):
            return None

    # ------------------------------------------------------------------
    # Blackboard update — called after each tool execution
    # ------------------------------------------------------------------

    def _update_blackboard(self, tool_name: str, tool_args: Dict[str, Any], tool_result: Dict[str, Any]) -> None:
        """Update WebStateBlackboard after each tool execution.

        Extracts: endpoints, forms, params, tech_stack, evidence, flags.
        """
        # Ingest the raw tool result for auto-extraction
        self._blackboard.ingest_tool_result(tool_name, tool_args, tool_result)

        # Detect route from new evidence
        self._detect_route_from_evidence()

    def _detect_route_from_evidence(self) -> None:
        """Update current route based on blackboard evidence scores."""
        summary = self._blackboard.state_summary()
        top_evidence = summary.get("top_evidence", [])
        if not top_evidence:
            # If no evidence yet, check interesting params for route hints
            params = summary.get("interesting_params", [])
            all_routes: set = set()
            for p in params:
                for route in p.get("suspected_routes", []):
                    all_routes.add(route)
            if all_routes:
                # Pick highest-priority route
                priority_order = ["source_leak", "ssti", "sqli", "cmdi", "lfi", "jwt", "upload", "ssrf", "php_pop"]
                for route in priority_order:
                    if route in all_routes:
                        if self._current_route != route:
                            self._current_route = route
                            log.info("Route switched to %s (from params)", route)
                        return
            return

        # Follow evidence scores
        best = top_evidence[0]
        best_route = best.get("route", "recon")
        best_score = best.get("score", 0)

        if best_score >= 0.5 and best_route != self._current_route and best_route != "recon":
            self._current_route = best_route
            log.info("Route switched to %s (evidence score: %.2f)", best_route, best_score)

    def _get_current_route_card_info(self) -> Dict[str, Any]:
        """Get current route info for diagnostics."""
        card = get_route_card(self._current_route)
        return {
            "route": self._current_route,
            "triggers": card.triggers[:3],
            "probes_count": len(card.probes),
            "blackboard_endpoints": len(self._blackboard.endpoints),
            "blackboard_evidence": len(self._blackboard.evidence),
        }

    def _knowledge_query(self) -> str:
        parts = [self.challenge_type or "", self.target]
        for analysis in self._source_analyses:
            parts.extend(finding.kind for finding in analysis.findings[:30])
            parts.extend(Path(item.get("path", "")).suffix for item in analysis.files[:20])
        return " ".join(part for part in parts if part)

    def _run_deterministic_helpers(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if self._capability is not None:
            return self._capability.run_helpers(
                agent=self,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_result=tool_result,
            )
        return None

    def _call_llm(self) -> Dict[str, Any]:
        """Call the LLM with current messages and tool definitions."""
        return self._llm.chat(
            messages=self._messages,
            tools=self._tool_definitions(),
            tool_choice="auto",
            thinking=self.thinking,
            reasoning_effort="max",
            max_tokens=4096,
        )

    def _fix_message_history(self) -> None:
        """Fix message history when tool_calls messages lack corresponding tool responses.

        DeepSeek API requires that every assistant message with tool_calls is
        immediately followed by tool response messages for each tool_call_id.
        This method scans the history and removes orphaned tool_calls or adds
        placeholder tool responses.
        """
        fixed: List[Dict[str, Any]] = []
        i = 0
        messages = self._messages
        while i < len(messages):
            msg = messages[i]
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                # Collect expected tool_call_ids
                expected_ids = {tc["id"] for tc in msg["tool_calls"]}
                # Look ahead for tool responses
                j = i + 1
                found_ids: set = set()
                while j < len(messages) and messages[j].get("role") == "tool":
                    tcid = messages[j].get("tool_call_id", "")
                    if tcid in expected_ids:
                        found_ids.add(tcid)
                    j += 1
                if found_ids == expected_ids:
                    # All tool responses present — keep as-is
                    for k in range(i, j):
                        fixed.append(messages[k])
                    i = j
                elif found_ids:
                    # Partial responses — add placeholders for missing ones
                    fixed.append(msg)
                    for k in range(i + 1, j):
                        fixed.append(messages[k])
                    for missing_id in expected_ids - found_ids:
                        fixed.append({
                            "role": "tool",
                            "tool_call_id": missing_id,
                            "content": '{"error": "tool execution was interrupted"}',
                        })
                    i = j
                else:
                    # No tool responses at all — add placeholders for all
                    fixed.append(msg)
                    for tc in msg["tool_calls"]:
                        fixed.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": '{"error": "tool execution was interrupted"}',
                        })
                    i += 1
            else:
                fixed.append(msg)
                i += 1
        self._messages.clear()
        self._messages.extend(fixed)

    def _tool_definitions(self) -> List[Dict[str, Any]]:
        return self._tool_router.definitions()

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with resilience layer via ActionRuntime."""
        # Check deduplication before executing
        is_duplicate = not self._strategy.should_attempt(name, args)

        # Route retryable tools through ActionRuntime for classification and retry
        action_result = None
        if name in {"http_request", "run_python", "run_tool_script"}:
            action_result = self._action_runtime.run(name, args)
            self._last_action_result = action_result
            if not action_result.success:
                self._emit(
                    "ctf_error",
                    tool=name,
                    error_type=action_result.error_type,
                    retryable=action_result.retryable,
                    observations=action_result.parsed_observations,
                )
            result = action_result.raw_output
        else:
            # Non-retryable tools go directly through tool_router
            result = self._tool_router.execute(name, args)
            self._last_action_result = None

        # Crypto/encoding hint extraction for web responses
        if name == "http_request" and result.get("body"):
            crypto_hint = _extract_crypto_hints_value(str(result["body"]))
            if crypto_hint:
                result = dict(result)
                result["_crypto_hint"] = crypto_hint
            # Update web session flow state (forms, login, CSRF)
            url = args.get("url", "")
            self._flow_manager.observe_result(url, result)
            # Inject CSRF token if present and not already in params/form
            csrf_tokens = self._flow_manager.csrf.get_tokens()
            if csrf_tokens:
                result = dict(result)
                result["_csrf_tokens"] = csrf_tokens

        # Annotate duplicates so the LLM sees the warning
        if is_duplicate:
            result = dict(result)
            result["_duplicate_warning"] = (
                f"注意：此次 {name} 调用与之前一次完全相同，参数未变化。"
                "请勿重复相同请求，应修改参数或切换攻击路线。"
            )

        return result

    def _normalise_enabled_tools(self, enabled_tools: Optional[List[str]]) -> Set[str]:
        registered_ctf_tools = {
            tool.name
            for tool in ToolRegistry.by_category("ctf_web")
            if tool.availability(self.runtime_config)["enabled"]
        }
        allowed = CORE_TOOL_NAMES | registered_ctf_tools
        if not self.runtime_config.ctf_auto_tooling_enabled:
            allowed -= {"write_tool_script", "run_tool_script", "install_python_package", "download_tool_url"}
        elif not self.runtime_config.ctf_tool_install_enabled:
            allowed -= {"install_python_package"}
        if not enabled_tools:
            return allowed
        selected = {tool for tool in enabled_tools if tool in allowed}
        selected.add("scan_flag")
        if "ctf_tool_manager" in allowed:
            selected.add("ctf_tool_manager")
        return selected

    def _check_flag_in_text(self, text: str) -> Optional[str]:
        """Check if text contains a flag (via FLAG_FOUND marker or pattern scan)."""
        return _check_flag_in_text_value(
            text,
            flag_engine=self._flag_engine,
            flag_format=self.flag_format,
        )

    async def _solve_multi_agent(self, start_time: float) -> Dict[str, Any]:
        """Hybrid solve: MultiAgentOrchestrator first, then ReAct LLM fallback.

        .. deprecated::
            This method is a **legacy** parallel execution path retained only
            for backward compatibility and as a fallback when CTFSolvePipeline
            is not used.

            The **canonical** parallel AI execution path is now:
                CTFSolvePipeline.run() → Phase2Runner
            which provides:
              - Evidence-driven dynamic worker assignment (via ParallelScanOutput)
              - Structured phase transitions with StallDetector
              - DiscoveryBroadcast for inter-worker communication
              - ExperienceWriter integration for knowledge accumulation
              - Unified SolveResult with full attribution

            New features and enhancements should be implemented in
            ``CTFSolvePipeline`` + ``Phase2Runner`` only. Do NOT add new
            logic here to avoid dual-maintenance divergence.

        Legacy Strategy (kept for reference):
          1. Run deterministic state machine routes (fast, zero API cost)
          2. If flag found → return immediately
          3. Phase 1.5: Parallel LLM race (3 workers × 5 turns each)
          4. If not found → fall back to full LLM ReAct loop with remaining budget
             The LLM gets the blackboard state as context so it doesn't repeat
             what the state machine already tried.
        """
        # --- DEPRECATION WARNING ---
        # This method is a legacy parallel execution path. The canonical path
        # is CTFSolvePipeline + Phase2Runner. See solve_pipeline.py.
        warnings.warn(
            "CTFReActAgent._solve_multi_agent() is deprecated. "
            "Use CTFSolvePipeline + Phase2Runner for parallel AI execution.",
            DeprecationWarning,
            stacklevel=2,
        )
        log.warning(
            "Using legacy _solve_multi_agent() path. Prefer CTFSolvePipeline "
            "+ Phase2Runner for parallel AI execution with full feature support."
        )

        from .multi_agent import MultiAgentOrchestrator

        # Emit progress so Web UI knows Phase 1 is starting
        self._emit(
            "ctf_iteration_start",
            iteration=0,
            max_iterations=self.max_iterations,
            phase="deterministic",
            message="Running deterministic exploit routes (Phase 1)...",
        )

        # Phase 1: Deterministic multi-agent (fast path)
        # Dynamic round budget based on evidence strength after recon
        phase1_timeout = min(60, self.timeout // 3)  # Max 60s or 1/3 of total timeout
        orch = MultiAgentOrchestrator(
            target_url=self.target,
            flag_format=self.flag_format,
            max_rounds=15,
            session=self._session,
        )

        # Dynamic budget: run recon first, then decide rounds
        phase1_rounds = self._compute_dynamic_rounds(orch)

        try:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(orch.run_loop, max_rounds=phase1_rounds)
                found, flag, action_log = future.result(timeout=phase1_timeout)
        except concurrent.futures.TimeoutError:
            log.warning("Phase 1 timed out after %ds", phase1_timeout)
            found, flag, action_log = False, None, []
        except Exception as e:
            log.warning("MultiAgentOrchestrator crashed: %s", e)
            found, flag, action_log = False, None, []

        # Emit Phase 1 completion
        phase1_rounds_used = len(set(e.get("round", 0) for e in action_log))
        self._emit(
            "ctf_tool_finish",
            iteration=0,
            tool="multi_agent_orchestrator",
            arguments={"routes_tried": phase1_rounds_used},
            result_preview=f"Phase 1 complete: {'flag found' if found else 'no flag'}, {phase1_rounds_used} rounds",
        )

        if found and flag:
            duration_ms = int((time.time() - start_time) * 1000)
            self._steps = action_log
            self._emit("ctf_flag_found", flag=flag, iterations=phase1_rounds_used)
            return self._result(
                success=True,
                flag=flag,
                reasoning=f"Multi-Agent deterministic: flag found in {phase1_rounds_used} rounds",
                duration_ms=duration_ms,
            )

        # Phase 1.5: Parallel LLM race (3 workers × 5 turns each)
        elapsed = time.time() - start_time
        remaining_time = self.timeout - elapsed
        if remaining_time > 45:
            bb_summary = orch.get_state_summary()
            top_routes = self._get_top_routes_from_evidence(orch)
            if top_routes:
                self._emit("ctf_parallel_race_start", routes=top_routes)
                race_flag = self._parallel_llm_race(top_routes, bb_summary)
                if race_flag:
                    duration_ms = int((time.time() - start_time) * 1000)
                    return self._result(
                        success=True,
                        flag=race_flag,
                        reasoning=f"Parallel LLM race found flag via routes: {top_routes}",
                        duration_ms=duration_ms,
                    )

        # Phase 2: LLM ReAct fallback with remaining budget
        elapsed = time.time() - start_time
        remaining_time = self.timeout - elapsed
        remaining_iters = max(5, self.max_iterations - phase1_rounds_used)

        if remaining_time < 30:
            # Not enough time for LLM fallback
            duration_ms = int(elapsed * 1000)
            self._emit(
                "ctf_tool_finish",
                iteration=0,
                tool="timeout_check",
                arguments={},
                result_preview=f"No time for LLM fallback (remaining: {remaining_time:.0f}s)",
            )
            return self._result(
                success=False,
                reasoning=f"Multi-Agent exhausted {phase1_rounds_used} rounds, no time for LLM fallback",
                duration_ms=duration_ms,
                error="flag_not_found",
            )

        log.info(
            "Multi-Agent failed after %d rounds. Falling back to LLM ReAct "
            "(remaining: %d iters, %.0fs)",
            phase1_rounds_used, remaining_iters, remaining_time,
        )
        self._emit(
            "ctf_multi_agent_fallback",
            reason="deterministic_routes_exhausted",
            remaining_iters=remaining_iters,
            remaining_time=int(remaining_time),
        )

        # Inject blackboard context into LLM messages so it knows what was tried
        bb_summary = orch.get_state_summary()
        tried_routes = list(bb_summary["coordinator"]["route_attempts"].keys())

        # Phase 2: Parallel LLM racing (3 workers × 5 iters each)
        # Each worker gets a different attack direction hint
        direction_hints = [
            "Focus on SQL injection and authentication bypass. Try stacked queries, "
            "UNION-based injection, login form bypass, and cookie manipulation.",
            "Focus on file inclusion, source code audit, and SSTI. Try LFI with php "
            "filters, directory traversal, template injection, and PHP deserialization.",
            "Focus on command injection, file upload, and SSRF. Try $IFS bypass, "
            "backtick injection, webshell upload, and internal service access.",
        ]

        self._emit(
            "ctf_parallel_phase2_start",
            workers=len(direction_hints),
            remaining_time=int(remaining_time),
        )

        phase2_flag = self._run_parallel_llm_phase2(
            direction_hints=direction_hints,
            tried_routes=tried_routes,
            bb_summary=bb_summary,
            max_iters_per_worker=5,
            time_cap=remaining_time,
        )

        if phase2_flag:
            duration_ms = int((time.time() - start_time) * 1000)
            return self._result(
                success=True,
                flag=phase2_flag,
                reasoning=f"Parallel LLM Phase 2 found flag after {phase1_rounds_used} deterministic rounds",
                duration_ms=duration_ms,
            )

        # If parallel workers didn't find it, fall back to single sequential ReAct
        elapsed = time.time() - start_time
        remaining_time = self.timeout - elapsed
        if remaining_time < 20:
            duration_ms = int(elapsed * 1000)
            return self._result(
                success=False,
                reasoning="Multi-Agent + parallel LLM exhausted, no time for sequential fallback",
                duration_ms=duration_ms,
                error="flag_not_found",
            )

        context_msg = (
            f"[System] The deterministic exploit engine already tried these routes "
            f"without finding the flag: {', '.join(tried_routes)}.\n"
            f"Evidence collected: {bb_summary['blackboard'].get('top_evidence', [])[:3]}\n"
            f"Parallel LLM workers also failed. Now YOU must analyze the target "
            f"creatively. Use http_request to interact with the target and run_python "
            f"for complex payloads. Do NOT repeat the same approaches that already failed."
        )

        # Switch to standard ReAct mode with reduced budget
        self.multi_agent = False  # Prevent recursion
        self.max_iterations = max(3, remaining_iters - 5)
        self.timeout = int(remaining_time)

        # Inject context before starting ReAct
        self._messages.clear()
        self._messages.extend(self._build_initial_messages())
        self._messages.append({"role": "user", "content": context_msg})

        # Run the standard ReAct loop (this calls _call_llm iteratively)
        from ..orchestrator.llm_client import LLMClient
        try:
            self._llm = LLMClient()
            if not self._llm.enabled:
                duration_ms = int((time.time() - start_time) * 1000)
                return self._result(
                    False,
                    duration_ms=duration_ms,
                    error="LLM not available for fallback",
                )
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return self._result(False, duration_ms=duration_ms, error=f"LLM init failed: {e}")

        # Run ReAct loop inline (same logic as solve() but without re-init)
        result = await self.solve()
        # Restore multi_agent flag
        self.multi_agent = True
        return result

    def _compute_dynamic_rounds(self, orch) -> int:
        """Compute dynamic Phase 1 round budget based on evidence strength.

        - If recon finds strong evidence for 1-2 routes → 5 rounds (fast path)
        - If no strong evidence → 10 rounds (try more routes)
        - Never exceed 15
        """
        # Run a quick recon to get initial evidence
        try:
            recon_decision = orch.recon.decide()
            orch.recon.execute(recon_decision)
            # Record the recon round
            orch.coordinator.record_result("recon", False)
        except Exception:
            return 15  # Fallback to max

        # Check evidence strength
        strong_evidence = [
            e for e in orch.blackboard.evidence
            if e.score >= 0.7 and e.route != "recon"
        ]
        routes_with_strong = set(e.route for e in strong_evidence)

        if len(routes_with_strong) >= 1 and len(routes_with_strong) <= 2:
            # Strong evidence for 1-2 routes — fast path
            return 5
        elif not strong_evidence:
            # No strong evidence — try more routes
            return 10
        else:
            # Multiple routes with evidence — standard budget
            return 15

    def _get_top_routes_from_evidence(self, orch) -> List[str]:
        """Get top 3 most promising routes from orchestrator evidence."""
        evidence_by_route: Dict[str, float] = {}
        for ev in orch.blackboard.evidence:
            if ev.route and ev.route != "recon":
                current = evidence_by_route.get(ev.route, 0.0)
                evidence_by_route[ev.route] = max(current, ev.score)

        # Sort by score descending, take top 3
        sorted_routes = sorted(evidence_by_route.items(), key=lambda x: x[1], reverse=True)
        return [r for r, s in sorted_routes[:3] if s > 0.1]

    def _parallel_llm_race(self, routes: List[str], bb_summary: Dict) -> Optional[str]:
        """Race multiple LLM workers in parallel, each trying a different route.

        Each worker gets its own session and 5 iterations to find the flag.
        First worker to find a flag wins — others are cancelled.
        Uses MultiModelClient for model diversity when multiple providers are configured.
        """
        import concurrent.futures
        import threading

        from ..orchestrator.llm_client import MultiModelClient

        cancel_event = threading.Event()
        flag_pattern = re.compile(self.flag_format, re.IGNORECASE)
        multi = MultiModelClient()

        def worker(route: str, worker_index: int) -> Optional[str]:
            """Mini-agent worker focused on a single route."""
            if cancel_event.is_set():
                return None

            try:
                llm = multi.get_client_for_worker(worker_index)
                if not llm.enabled:
                    return None
            except Exception:
                return None

            worker_session = requests.Session()
            worker_session.headers.update({"User-Agent": "AutoPenX-CTF/1.0"})

            # Build route-specific prompt
            system_prompt = (
                f"You are a CTF exploit specialist focused on the '{route}' attack vector.\n"
                f"Target: {self.target}\n"
                f"Your goal: find the flag (format: {self.flag_format}).\n"
                f"Evidence from recon: {bb_summary.get('blackboard', {}).get('top_evidence', [])[:2]}\n"
                f"You have 5 turns. Each turn, output a JSON object with:\n"
                f'{{"method": "GET|POST", "url": "...", "data": "...", "headers": {{}}}}\n'
                f"Focus ONLY on {route} techniques. Be creative with payloads."
            )

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Start exploiting {route} on {self.target}. Output your first HTTP request as JSON."},
            ]

            for turn in range(5):
                if cancel_event.is_set():
                    return None

                try:
                    response = llm.chat(messages, temperature=0.7, max_tokens=500)
                    content = response.get("content", "")

                    # Try to parse HTTP request from LLM output
                    req_data = self._parse_llm_http_request(content)
                    if not req_data:
                        messages.append({"role": "assistant", "content": content})
                        messages.append({"role": "user", "content": "Invalid format. Output a valid JSON HTTP request."})
                        continue

                    # Execute the request
                    try:
                        method = req_data.get("method", "GET").upper()
                        url = req_data.get("url", self.target)
                        headers = req_data.get("headers", {})
                        data = req_data.get("data")

                        if method == "POST":
                            resp = worker_session.post(url, data=data, headers=headers, timeout=8)
                        else:
                            resp = worker_session.get(url, params=req_data.get("params"), headers=headers, timeout=8)

                        resp_text = resp.text[:2000]

                        # Check for flag
                        match = flag_pattern.search(resp_text)
                        if match:
                            cancel_event.set()
                            return match.group(0)

                        # Feed response back to LLM
                        messages.append({"role": "assistant", "content": content})
                        messages.append({
                            "role": "user",
                            "content": f"Response (HTTP {resp.status_code}, {len(resp.text)} bytes):\n{resp_text[:500]}\n\nAnalyze and try next payload.",
                        })

                    except requests.RequestException as e:
                        messages.append({"role": "assistant", "content": content})
                        messages.append({"role": "user", "content": f"Request failed: {e}. Try a different approach."})

                except Exception:
                    break

            return None

        # Launch workers in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(worker, r, idx): r for idx, r in enumerate(routes[:3])}
            try:
                for future in concurrent.futures.as_completed(futures, timeout=60):
                    try:
                        result = future.result(timeout=5)
                        if result:
                            cancel_event.set()
                            return result
                    except Exception:
                        continue
            except concurrent.futures.TimeoutError:
                cancel_event.set()

        return None

    def _run_parallel_llm_phase2(
        self,
        direction_hints: List[str],
        tried_routes: List[str],
        bb_summary: Dict,
        max_iters_per_worker: int = 5,
        time_cap: float = 120.0,
    ) -> Optional[str]:
        """Phase 2 parallel LLM racing: launch multiple workers with different attack directions.

        Each worker gets its own message history with a unique direction hint.
        Workers share the same session (for cookie persistence) and blackboard
        (so they don't repeat each other's failed attempts).
        First worker to find a flag wins — others are cancelled.

        Args:
            direction_hints: List of attack direction prompts for each worker.
            tried_routes: Routes already attempted by Phase 1.
            bb_summary: Blackboard state summary from Phase 1.
            max_iters_per_worker: Max iterations per worker (default 5).
            time_cap: Total time cap for Phase 2 in seconds.

        Returns:
            Flag string if found, None otherwise.
        """
        import concurrent.futures
        import threading

        from ..orchestrator.llm_client import MultiModelClient

        cancel_event = threading.Event()
        flag_pattern = re.compile(self.flag_format, re.IGNORECASE)
        multi = MultiModelClient()

        def worker(direction_hint: str, worker_id: int) -> Optional[str]:
            """LLM worker focused on a specific attack direction."""
            if cancel_event.is_set():
                return None

            try:
                llm = multi.get_client_for_worker(worker_id)
                if not llm.enabled:
                    return None
            except Exception:
                return None

            # Workers share the same session for cookie persistence
            worker_session = self._session

            # Build direction-specific system prompt
            system_prompt = (
                f"You are CTF exploit worker #{worker_id + 1}. Your attack direction:\n"
                f"{direction_hint}\n\n"
                f"Target: {self.target}\n"
                f"Flag format: {self.flag_format}\n"
                f"Routes already tried (failed): {', '.join(tried_routes)}\n"
                f"Evidence from recon: {bb_summary.get('blackboard', {}).get('top_evidence', [])[:3]}\n\n"
                f"You have {max_iters_per_worker} turns. Each turn, output a JSON object:\n"
                f'{{"method": "GET|POST", "url": "full_url", "data": "body_string_or_null", '
                f'"params": {{}}, "headers": {{}}}}\n\n'
                f"Be creative and aggressive. Try multiple payload variations. "
                f"Analyze each response carefully for flags, hints, or error messages "
                f"that reveal the next step."
            )

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": (
                    f"Start exploiting {self.target}. "
                    f"Output your first HTTP request as JSON. "
                    f"Remember: focus on {direction_hint.split('.')[0].lower()}."
                )},
            ]

            for turn in range(max_iters_per_worker):
                if cancel_event.is_set():
                    return None

                try:
                    response = llm.chat(messages, temperature=0.7, max_tokens=600)
                    content = response.get("content", "")

                    # Try to parse HTTP request from LLM output
                    req_data = self._parse_llm_http_request(content)
                    if not req_data:
                        messages.append({"role": "assistant", "content": content})
                        messages.append({"role": "user", "content": (
                            "Invalid format. Output a valid JSON HTTP request with "
                            "at minimum 'method' and 'url' fields."
                        )})
                        continue

                    # Execute the request using the shared session
                    try:
                        method = req_data.get("method", "GET").upper()
                        url = req_data.get("url", self.target)
                        headers = req_data.get("headers") or {}
                        data = req_data.get("data")
                        params = req_data.get("params")

                        if method == "POST":
                            resp = worker_session.post(
                                url, data=data, params=params,
                                headers=headers, timeout=8,
                            )
                        else:
                            resp = worker_session.get(
                                url, params=params,
                                headers=headers, timeout=8,
                            )

                        resp_text = resp.text[:3000]

                        # Check for flag in response
                        match = flag_pattern.search(resp_text)
                        if match:
                            cancel_event.set()
                            log.info(
                                "Phase 2 worker #%d found flag on turn %d",
                                worker_id + 1, turn + 1,
                            )
                            return match.group(0)

                        # Record to shared blackboard so other workers see it
                        try:
                            self._blackboard.record_attempt(
                                route=f"llm_worker_{worker_id}",
                                tool="http_request",
                                args={"url": url, "method": method},
                                success=False,
                                result_summary=f"HTTP {resp.status_code}, {len(resp.text)} bytes",
                                failure_reason="no_flag",
                            )
                        except Exception:
                            pass

                        # Feed response back to LLM for next iteration
                        messages.append({"role": "assistant", "content": content})
                        messages.append({
                            "role": "user",
                            "content": (
                                f"Response (HTTP {resp.status_code}, {len(resp.text)} bytes):\n"
                                f"{resp_text[:800]}\n\n"
                                f"Analyze this response. Look for flags, hints, error messages, "
                                f"or clues. Then try your next payload."
                            ),
                        })

                    except requests.RequestException as e:
                        messages.append({"role": "assistant", "content": content})
                        messages.append({"role": "user", "content": (
                            f"Request failed: {e}. Try a different URL or approach."
                        )})

                except Exception as exc:
                    log.debug("Phase 2 worker #%d error: %s", worker_id + 1, exc)
                    break

            return None

        # Launch workers in parallel (one per direction hint)
        num_workers = min(3, len(direction_hints))
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {
                executor.submit(worker, hint, idx): idx
                for idx, hint in enumerate(direction_hints[:num_workers])
            }
            try:
                for future in concurrent.futures.as_completed(futures, timeout=time_cap):
                    try:
                        result = future.result(timeout=5)
                        if result:
                            cancel_event.set()
                            self._emit(
                                "ctf_parallel_phase2_done",
                                worker=futures[future],
                                flag=result,
                            )
                            return result
                    except Exception:
                        continue
            except concurrent.futures.TimeoutError:
                cancel_event.set()
                log.warning("Phase 2 parallel workers timed out after %.0fs", time_cap)

        return None

    def _parse_llm_http_request(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse an HTTP request JSON from LLM output."""
        # Try to find JSON in the content
        try:
            # Direct JSON parse
            data = json.loads(content)
            if isinstance(data, dict) and ("url" in data or "method" in data):
                return data
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code block
        json_match = re.search(r'```(?:json)?\s*(\{[^`]+\})\s*```', content, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass

        # Try to find any JSON object in the text
        brace_match = re.search(r'\{[^{}]*"(?:url|method)"[^{}]*\}', content)
        if brace_match:
            try:
                data = json.loads(brace_match.group(0))
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass

        return None

    def _result(
        self,
        success: bool,
        flag: Optional[str] = None,
        reasoning: str = "",
        duration_ms: int = 0,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build the final result dict."""
        if reasoning:
            self._state.add_reasoning(reasoning)
        return self._state.build_result(
            success=success,
            flag=flag,
            duration_ms=duration_ms,
            error=error,
        )

    def _record_attempt(self, result: Dict[str, Any]) -> None:
        """Record every completed attempt to the persistent CTF knowledge base."""
        try:
            profile = self._build_profile_from_context()
            tools_used = [step.get("tool") for step in self._steps if step.get("tool")]
            blockers = _extract_blockers_value(self._steps, result)
            self._kb.record_attempt(profile, {
                "success": result.get("success"),
                "flag": result.get("flag", ""),
                "target": self.target,
                "steps_executed": result.get("iterations", 0),
                "duration_ms": result.get("duration_ms", 0),
                "strategy_used": self._summarize_strategy(),
                "error": result.get("error", ""),
                "tools_used": tools_used,
                "lessons": _extract_lessons_value(self._steps, result),
                "blockers": blockers,
            })
        except Exception as e:
            log.warning("Failed to record CTF attempt: %s", e)

    def _build_profile_from_context(self) -> ChallengeProfile:
        try:
            ct = ChallengeType(self.challenge_type) if self.challenge_type else ChallengeType.UNKNOWN
        except ValueError:
            ct = ChallengeType.UNKNOWN
        tech_stack: List[str] = []
        potential_vulns: List[str] = []
        key_hints: List[str] = []
        for analysis in self._source_analyses:
            for item in analysis.files:
                suffix = Path(item.get("path", "")).suffix.lower()
                if suffix == ".php" and "PHP" not in tech_stack:
                    tech_stack.append("PHP")
                if suffix == ".js" and "JavaScript" not in tech_stack:
                    tech_stack.append("JavaScript")
            for finding in analysis.findings:
                kind = finding.kind
                if kind not in potential_vulns:
                    potential_vulns.append(kind)
                key_hints.append(f"{finding.file}:{finding.kind}")
        return ChallengeProfile(
            challenge_type=ct,
            sub_type="source-assisted" if self._source_analyses else "",
            tech_stack=tech_stack[:10],
            potential_vulns=potential_vulns[:20],
            key_hints=key_hints[:20],
            confidence=0.85 if self._source_analyses else 0.5,
        )

    def _summarize_strategy(self) -> str:
        """Summarize the attack path from executed steps."""
        if not self._steps:
            return "unknown"
        parts = []
        for step in self._steps:
            tool = step.get("tool", "")
            args = step.get("args", {})
            if tool == "http_request":
                url = args.get("url", "")
                method = args.get("method", "GET")
                # Extract path from URL
                path = url.split("//", 1)[-1].split("/", 1)[-1] if "//" in url else url
                parts.append(f"{method} /{path[:50]}")
            elif tool == "run_python":
                code = args.get("code", "")
                # Extract first meaningful line
                lines = [ln.strip() for ln in code.split("\n") if ln.strip() and not ln.strip().startswith("#")]
                if lines:
                    parts.append(f"python: {lines[0][:60]}")
            elif tool == "decode_data":
                enc = args.get("encoding", "auto")
                parts.append(f"decode({enc})")
            elif tool:
                parts.append(tool)
        # Summarize to a reasonable length
        summary = " → ".join(parts[:8])
        if len(parts) > 8:
            summary += f" → ... ({len(parts)} steps total)"
        return summary or "unknown"

    # ------------------------------------------------------------------
    # Phase 6: multi-agent worker helpers
    # ------------------------------------------------------------------

    def _collect_worker_results(self, iteration: int) -> Optional[str]:
        """Ingest completed worker tasks from consensus and return flag if found."""
        try:
            ingested = self._consensus.ingest_from_queue()
            if ingested == 0:
                return None
            decision = self._consensus.decide()
            self._emit("ctf_consensus_decision", **decision.to_dict())
            # Inject high-value worker evidence into LLM context
            if decision.verdict == "route_suggestion" and decision.next_action:
                self._messages.append({
                    "role": "user",
                    "content": f"Worker 侦察建议: {decision.next_action}",
                })
            if decision.verdict == "evidence" and decision.evidence:
                ev_text = "\n".join(
                    f"- {e.get('summary', '')}" for e in decision.evidence[:3]
                )
                if ev_text:
                    self._messages.append({
                        "role": "user",
                        "content": f"Worker 收集到的证据:\n{ev_text}",
                    })
            return decision.flag if decision.flag else None
        except Exception as exc:
            log.warning("collect_worker_results error: %s", exc)
            return None

    def _stop_workers(self) -> None:
        """Gracefully stop all background worker threads."""
        for w in getattr(self, "_worker_threads", []):
            try:
                w.stop(timeout=3.0)
            except Exception as exc:  # noqa: BLE001
                log.warning("Error stopping worker %s: %s", w.worker_id, exc)
        # Mark remaining queued tasks as cancelled
        if hasattr(self, "_task_queue"):
            self._task_queue.cancel_all(reason="session_ended")
