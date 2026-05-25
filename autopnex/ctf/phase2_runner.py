"""Phase 2 parallel LLM racing runner and worker implementation.

This module defines the data models for Phase 2 racing results, the
Phase2Runner orchestrator that spawns and races parallel LLM workers,
and the Phase2Worker thread that executes tool-calling loops.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.3, 6.4, 6.5,
              6.6, 7.1, 7.2, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 8.5,
              8.6, 9.1, 9.2, 10.1, 10.2, 11.2, 11.4, 11.6
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from autopnex.ctf.attribution import Attribution
from autopnex.ctf.discovery_broadcast import DiscoveryBroadcast

if TYPE_CHECKING:
    import requests
    from autopnex.ctf.flag_engine import FlagEngine
    from autopnex.ctf.parallel_route_scan import ParallelScanOutput, ScanResult
    from autopnex.ctf.solve_pipeline import PipelineConfig
    from autopnex.ctf.tool_router import ToolRouter
    from autopnex.ctf.web_state_blackboard import WebStateBlackboard
    from autopnex.orchestrator.llm_client import LLMClient
    from config.settings import RuntimeConfig

log = logging.getLogger("autopnex.ctf.phase2_runner")


# ---------------------------------------------------------------------------
# WorkerAssignment — Dynamic Worker Assignment Descriptor
# ---------------------------------------------------------------------------


@dataclass
class WorkerAssignment:
    """Describes a single worker's assignment based on ParallelScanOutput.

    Used by _assign_workers() to map scan results to concrete worker
    configurations. Each assignment carries the route, variant, strategy
    hint, scan evidence, and exploit steps for the worker's system prompt.

    Attributes:
        route: The attack route name (e.g., "sqli", "lfi", "ssti").
        variant: Variant identifier for dual-worker routes ("variant_a",
            "variant_b") or "default" for single-worker routes.
        strategy_hint: Human-readable strategy hint for the worker prompt.
        scan_result: The ScanResult from ParallelScanOutput for this route,
            or None if using static fallback.
        exploit_steps: Ordered exploit steps from the route's state machine,
            injected into the worker's system prompt as deterministic guidance.
    """

    route: str
    variant: str = "default"
    strategy_hint: str = ""
    scan_result: Optional[Any] = None
    exploit_steps: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class WorkerResult:
    """Result produced by a single Phase2Worker after its racing run.

    Captures the outcome of one worker's tool-calling loop, including
    whether it found a flag, how many resources it consumed, and whether
    it was cancelled by another worker's success.

    Attributes:
        worker_id: Unique identifier for this worker thread.
        strategy_hint: The attack direction assigned to this worker.
        success: Whether this worker found a valid flag.
        flag: The captured flag string, if found.
        turns_completed: Number of LLM turn iterations completed.
        api_calls: Number of LLM API calls made by this worker.
        tokens_used: Total tokens consumed across all API calls.
        winning_tool_call: Description of the tool call that produced the flag.
        error: Error message if the worker terminated abnormally.
        cancelled: Whether this worker was stopped by cooperative cancellation.
    """

    worker_id: str
    strategy_hint: str
    success: bool
    flag: Optional[str] = None
    turns_completed: int = 0
    api_calls: int = 0
    tokens_used: int = 0
    winning_tool_call: Optional[str] = None
    error: Optional[str] = None
    cancelled: bool = False
    route: Optional[str] = None
    variant: Optional[str] = None
    # Task 4.9: Runtime enhancement stats for debugging/benchmark
    duplicate_calls_detected: int = 0
    stagnation_warnings: int = 0
    discoveries_received: int = 0
    discoveries_published: int = 0
    # Task 6.4: Context compression stats
    compression_count: int = 0
    estimated_discarded_tokens: int = 0
    retained_messages: int = 0
    # Task 6.6: Reasoning log from <plan>/<hypothesis> blocks
    reasoning_log: List[str] = field(default_factory=list)
    # Task 7.6: Dynamic tool unlocks recorded during runtime
    tools_unlocked: List[str] = field(default_factory=list)


@dataclass
class Phase2Result:
    """Aggregate result from the Phase 2 parallel LLM racing round.

    Returned by Phase2Runner.run() after all workers complete, are
    cancelled, or time out. Contains the winning result (if any) and
    summaries from all workers for reporting.

    Attributes:
        success: Whether any worker found a valid flag.
        flag: The captured flag string from the winning worker.
        winning_worker_id: ID of the worker that found the flag.
        attribution: Full attribution metadata for the winning solve.
        worker_summaries: Per-worker summary dicts for benchmark reporting.
        total_turns: Sum of turns completed across all workers.
        total_api_calls: Sum of API calls made across all workers.
    """

    success: bool
    flag: Optional[str] = None
    winning_worker_id: Optional[str] = None
    attribution: Optional[Attribution] = None
    worker_summaries: List[Dict[str, Any]] = field(default_factory=list)
    total_turns: int = 0
    total_api_calls: int = 0
    winning_route: Optional[str] = None
    winning_variant: Optional[str] = None
    winning_assignment: Optional[WorkerAssignment] = None


# ---------------------------------------------------------------------------
# Phase2Runner — Parallel LLM Racing Orchestrator
# ---------------------------------------------------------------------------


class Phase2Runner:
    """Orchestrates parallel LLM worker racing for Phase 2.

    Spawns a configurable number of Phase2Worker threads, each with an
    independent session, LLM client, and strategy hint. Workers race to
    find a flag; the first to succeed triggers cooperative cancellation
    of all others.

    Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 7.1, 7.2, 8.1, 8.6, 9.1
    """

    def __init__(
        self,
        config: "PipelineConfig",
        blackboard: Optional["WebStateBlackboard"],
        session: Optional["requests.Session"],
        flag_engine: Optional["FlagEngine"],
        runtime_config: Optional["RuntimeConfig"],
        scan_output: Optional[Any] = None,
    ) -> None:
        self.config = config
        self.blackboard = blackboard
        self.session = session
        self.flag_engine = flag_engine
        self.runtime_config = runtime_config
        self.scan_output = scan_output
        self.discovery_broadcast = DiscoveryBroadcast()

    def run(self) -> Phase2Result:
        """Spawn workers, race them, return winning result or failure.

        Creates independent sessions, assigns strategies, spawns worker
        threads, and waits for completion or timeout. Returns the winning
        result with full attribution if a flag is found.

        Requirements: 5.1, 5.3, 5.4, 5.5, 5.6, 8.1, 8.6
        """
        from autopnex.ctf.tool_router import ToolRouter, CORE_TOOL_NAMES
        from autopnex.ctf.tool_workspace import CTFToolWorkspace
        from autopnex.orchestrator.llm_client import MultiModelClient

        worker_count = self.config.phase2_worker_count

        # Create shared cancel_event for cooperative cancellation (Req 8.1)
        cancel_event = threading.Event()

        # Create independent sessions for each worker (Req 7.1, 7.2)
        worker_sessions = self._create_worker_sessions()

        # Assign workers dynamically based on scan_output (Task 3.4, 3.5, 3.6)
        assignments = self._assign_workers()

        # Get blackboard summary for workers (Req 5.2)
        blackboard_summary: Dict[str, Any] = {}
        if self.blackboard is not None:
            blackboard_summary = self.blackboard.state_summary()

        # Determine target origin from blackboard or session
        target_origin = ""
        if self.blackboard is not None:
            target_origin = getattr(self.blackboard, "target_url", "")
        if not target_origin and self.session is not None:
            # Fallback: no target_url available
            target_origin = ""

        # Create LLM clients via MultiModelClient for provider diversity
        multi_client = MultiModelClient()

        # Build FlagEngine reference
        flag_engine = self.flag_engine
        if flag_engine is None:
            from autopnex.ctf.flag_engine import FlagEngine
            flag_engine = FlagEngine()

        # Spawn workers
        workers: List[Phase2Worker] = []
        for i in range(worker_count):
            worker_id = f"worker_{i}"
            assignment = assignments[i] if i < len(assignments) else WorkerAssignment(
                route="general", variant="default", strategy_hint="general"
            )
            strategy = assignment.strategy_hint
            llm_client = multi_client.get_client_for_worker(i)
            session = worker_sessions[i] if i < len(worker_sessions) else self._create_single_session()

            # Create a ToolRouter for this worker with its own session
            # Use a subset of tools appropriate for Phase 2 racing
            phase2_tools = {"http_request", "run_python", "scan_flag", "recon_scan"}

            # Conditionally include specialist tools (Req 14.1, 14.2)
            phase2_tools = self._resolve_conditional_tools(
                phase2_tools, strategy, blackboard_summary
            )

            workspace_root = (
                getattr(self.runtime_config, "ctf_workspace_dir", "ctf_workspace")
                if self.runtime_config else "ctf_workspace"
            )
            tool_workspace = CTFToolWorkspace(root=workspace_root)

            # Build a minimal knowledge base stub for ToolRouter
            class _MinimalKB:
                def search_knowledge(self, query: str, challenge_type: str = "", limit: int = 8) -> list:
                    return []

            tool_router = ToolRouter(
                runtime_config=self.runtime_config or _default_runtime_config(),
                flag_engine=flag_engine,
                tool_workspace=tool_workspace,
                knowledge_base=_MinimalKB(),
                session=session,
                enabled_tools=phase2_tools,
            )

            worker = Phase2Worker(
                worker_id=worker_id,
                strategy_hint=strategy,
                llm_client=llm_client,
                tool_router=tool_router,
                session=session,
                cancel_event=cancel_event,
                blackboard_summary=blackboard_summary,
                flag_engine=flag_engine,
                target_origin=target_origin,
                max_turns=self.config.phase2_max_turns_per_worker,
                max_tokens=self.config.max_tokens_per_worker,
                tool_timeout=30.0,
                discovery_broadcast=self.discovery_broadcast,
                assignment=assignment,
            )
            workers.append(worker)

        # Start all workers
        for w in workers:
            w.start()

        # Wait for workers with per-worker timeout (Req 8.6)
        per_worker_timeout = self.config.phase2_wall_clock_timeout_seconds
        for w in workers:
            w.join(timeout=per_worker_timeout)

        # If any worker is still alive after timeout, set cancel_event
        # to signal them to stop, then give a brief grace period
        if any(w.is_alive() for w in workers):
            cancel_event.set()
            for w in workers:
                if w.is_alive():
                    w.join(timeout=5.0)  # Brief grace period

        # Collect results from all workers (Req 5.5, 5.6)
        winning_result: Optional[WorkerResult] = None
        worker_summaries: List[Dict[str, Any]] = []
        total_turns = 0
        total_api_calls = 0

        for w in workers:
            wr = w.result
            total_turns += wr.turns_completed
            total_api_calls += wr.api_calls
            worker_summaries.append({
                "worker_id": wr.worker_id,
                "strategy_hint": wr.strategy_hint,
                "success": wr.success,
                "turns_completed": wr.turns_completed,
                "api_calls": wr.api_calls,
                "tokens_used": wr.tokens_used,
                "cancelled": wr.cancelled,
                "error": wr.error,
                "route": wr.route,
                "variant": wr.variant,
            })
            if wr.success and winning_result is None:
                winning_result = wr

        # Build Phase2Result
        if winning_result is not None:
            # Determine provider/model from the winning worker's LLM client
            winning_worker = next(
                (w for w in workers if w.worker_id == winning_result.worker_id), None
            )
            provider = ""
            model = ""
            if winning_worker is not None:
                provider = getattr(winning_worker.llm_client, "base_url", "") or ""
                model = getattr(winning_worker.llm_client, "model", "") or ""

            attribution = Attribution(
                solving_phase="phase2",
                worker_id=winning_result.worker_id,
                provider=provider,
                model=model,
                strategy_hint=winning_result.strategy_hint,
                turn_number=winning_result.turns_completed,
                winning_tool_call=winning_result.winning_tool_call,
                total_api_calls=total_api_calls,
                total_tokens_used=winning_result.tokens_used,
            )

            # Retrieve the winning assignment for attribution
            winning_assignment: Optional[WorkerAssignment] = None
            if winning_worker is not None:
                winning_assignment = getattr(winning_worker, "assignment", None)

            return Phase2Result(
                success=True,
                flag=winning_result.flag,
                winning_worker_id=winning_result.worker_id,
                attribution=attribution,
                worker_summaries=worker_summaries,
                total_turns=total_turns,
                total_api_calls=total_api_calls,
                winning_route=winning_result.route,
                winning_variant=winning_result.variant,
                winning_assignment=winning_assignment,
            )

        # No winner — return failure result (Req 5.6)
        return Phase2Result(
            success=False,
            worker_summaries=worker_summaries,
            total_turns=total_turns,
            total_api_calls=total_api_calls,
        )

    def _create_worker_sessions(self) -> List["requests.Session"]:
        """Clone cookies from Phase 1 session into independent sessions.

        Each worker gets its own requests.Session with cookies copied
        from the Phase 1 session, ensuring no shared mutable state.

        Requirements: 7.1, 7.2
        """
        import requests as req_lib

        worker_count = self.config.phase2_worker_count
        sessions: List[req_lib.Session] = []

        for _ in range(worker_count):
            new_session = req_lib.Session()
            # Clone cookies from Phase 1 session
            if self.session is not None:
                for cookie in self.session.cookies:
                    new_session.cookies.set_cookie(cookie)
                # Clone headers if present
                if self.session.headers:
                    new_session.headers.update(self.session.headers)
            sessions.append(new_session)

        return sessions

    def _create_single_session(self) -> "requests.Session":
        """Create a single independent session (fallback)."""
        import requests as req_lib

        new_session = req_lib.Session()
        if self.session is not None:
            for cookie in self.session.cookies:
                new_session.cookies.set_cookie(cookie)
        return new_session

    def _assign_strategies(self) -> List[str]:
        """Select strategy hints based on Phase 1 evidence and configured pool.

        Prioritizes strategies matching strong evidence from Phase 1.
        Ensures each worker gets a distinct strategy hint.

        Requirements: 9.1, 9.3
        """
        worker_count = self.config.phase2_worker_count
        pool = list(self.config.strategy_pool)
        assigned: List[str] = []

        # Check blackboard for strong evidence to prioritize (Req 9.3)
        prioritized: List[str] = []
        if self.blackboard is not None:
            scenario_hints = getattr(self.blackboard, "scenario_hints", [])
            for hint in scenario_hints:
                confidence = getattr(hint, "confidence", 0.0)
                if confidence >= 0.7:
                    route = getattr(hint, "route", "")
                    # Map route names to strategy pool entries
                    for strategy in pool:
                        if route.lower() in strategy.lower() or strategy.split("+")[0] in route.lower():
                            if strategy not in prioritized:
                                prioritized.append(strategy)

            # Also check evidence cards for strong vulnerability indicators
            evidence_cards = getattr(self.blackboard, "evidence", [])
            for card in evidence_cards:
                strength = getattr(card, "strength", None)
                route = getattr(card, "route", "")
                if strength and str(strength.value) in ("strong", "confirmed"):
                    for strategy in pool:
                        if route.lower() in strategy.lower() or strategy.split("+")[0] in route.lower():
                            if strategy not in prioritized:
                                prioritized.append(strategy)

        # Build final assignment: prioritized first, then fill from pool
        for strategy in prioritized:
            if len(assigned) >= worker_count:
                break
            assigned.append(strategy)
            if strategy in pool:
                pool.remove(strategy)

        # Fill remaining slots from pool (round-robin if pool is smaller)
        idx = 0
        while len(assigned) < worker_count:
            if pool:
                assigned.append(pool[idx % len(pool)])
                idx += 1
            else:
                # Fallback: use generic strategy
                assigned.append("general")
                break

        return assigned[:worker_count]

    def _assign_workers(self) -> List[WorkerAssignment]:
        """Dynamically assign workers based on ParallelScanOutput.

        If scan_output is available and has routes with score > 0.3, uses
        dynamic assignment:
          - Top-scoring route gets dual workers (variant_a / variant_b)
            if phase2_top_route_dual_worker is True.
          - Remaining routes above threshold get 1 worker each.
          - Total capped at phase2_worker_count.

        Falls back to static strategy_pool if no scan_output or no routes
        above threshold.

        Requirements: Task 3.4, 3.5, 3.6
        """
        worker_count = self.config.phase2_worker_count

        # --- Dynamic assignment from scan_output ---
        if (
            self.scan_output is not None
            and getattr(self.config, "phase2_dynamic_workers", True)
        ):
            results = getattr(self.scan_output, "results", [])
            viable_routes = [r for r in results if r.evidence_score > 0.3]

            if viable_routes:
                assignments: List[WorkerAssignment] = []

                # Top route gets dual workers if configured
                top = viable_routes[0]
                top_exploit_steps = self._get_exploit_steps_for_route(top.route)

                if getattr(self.config, "phase2_top_route_dual_worker", True):
                    # variant_a: primary payload family
                    assignments.append(WorkerAssignment(
                        route=top.route,
                        variant="variant_a",
                        strategy_hint=f"{top.route}:variant_a (primary payload family)",
                        scan_result=top,
                        exploit_steps=top_exploit_steps,
                    ))
                    # variant_b: alternative payload family
                    assignments.append(WorkerAssignment(
                        route=top.route,
                        variant="variant_b",
                        strategy_hint=f"{top.route}:variant_b (alternative payload family)",
                        scan_result=top,
                        exploit_steps=top_exploit_steps,
                    ))
                else:
                    assignments.append(WorkerAssignment(
                        route=top.route,
                        variant="default",
                        strategy_hint=f"{top.route} (top scoring route)",
                        scan_result=top,
                        exploit_steps=top_exploit_steps,
                    ))

                # Remaining viable routes get 1 worker each
                for route_result in viable_routes[1:]:
                    if len(assignments) >= worker_count:
                        break
                    route_steps = self._get_exploit_steps_for_route(route_result.route)
                    assignments.append(WorkerAssignment(
                        route=route_result.route,
                        variant="default",
                        strategy_hint=f"{route_result.route} (score={route_result.evidence_score:.2f})",
                        scan_result=route_result,
                        exploit_steps=route_steps,
                    ))

                # Cap at worker_count
                assignments = assignments[:worker_count]

                log.info(
                    "Dynamic worker assignment: %d workers assigned from %d viable routes",
                    len(assignments),
                    len(viable_routes),
                )
                for a in assignments:
                    log.debug(
                        "  → route=%s variant=%s hint=%s steps=%d",
                        a.route, a.variant, a.strategy_hint, len(a.exploit_steps),
                    )

                return assignments

        # --- Fallback: static strategy_pool ---
        log.info(
            "No viable scan_output routes (or dynamic workers disabled), "
            "falling back to static strategy_pool"
        )
        strategies = self._assign_strategies()
        return [
            WorkerAssignment(
                route=strategy.split("+")[0],
                variant="default",
                strategy_hint=strategy,
                scan_result=None,
                exploit_steps=[],
            )
            for strategy in strategies
        ]

    def _get_exploit_steps_for_route(self, route_name: str) -> List[Dict[str, Any]]:
        """Load exploit steps from the RouteStateMachine registry for a route.

        Returns an empty list if the route is not found or instantiation fails.
        """
        try:
            from autopnex.ctf.route_state_machine import MACHINE_REGISTRY

            machine_cls = MACHINE_REGISTRY.get(route_name)
            if machine_cls is None:
                return []

            # Get target_url from blackboard or empty string
            target_url = ""
            if self.blackboard is not None:
                target_url = getattr(self.blackboard, "target_url", "")

            # Instantiate machine to get exploit steps
            import requests as req_lib
            temp_session = req_lib.Session()
            machine = machine_cls(target_url or "http://target", session=temp_session)
            return machine.get_exploit_steps()
        except Exception as e:
            log.debug("Failed to load exploit steps for route '%s': %s", route_name, e)
            return []

    def _resolve_conditional_tools(
        self,
        base_tools: set,
        strategy_hint: str,
        blackboard_summary: Dict[str, Any],
    ) -> set:
        """Conditionally include specialist tools based on strategy and evidence.

        Adds blind_sqli_extract when the worker's strategy includes "sqli" and
        blackboard evidence suggests blind injection. Adds waf_bypass_generate
        to ALL workers since any worker might encounter a WAF-blocked response
        during execution.

        Requirements: 14.1, 14.2
        """
        tools = set(base_tools)

        # --- Requirement 14.1: blind_sqli_extract ---
        # Include when strategy_hint contains "sqli" AND evidence suggests blind injection
        if "sqli" in strategy_hint.lower():
            if self._has_blind_injection_indicators(blackboard_summary):
                tools.add("blind_sqli_extract")
                log.debug(
                    "Including blind_sqli_extract for strategy '%s' "
                    "(blind injection indicators found)",
                    strategy_hint,
                )

        # --- Requirement 14.2: waf_bypass_generate ---
        # Always include waf_bypass_generate for ALL workers since any worker
        # might encounter a WAF-blocked response during execution. WAF detection
        # happens dynamically at runtime, so the tool must be pre-available.
        tools.add("waf_bypass_generate")
        log.debug(
            "Including waf_bypass_generate for worker with strategy '%s' "
            "(available to all workers per Req 14.2)",
            strategy_hint,
        )

        return tools

    def _has_blind_injection_indicators(self, blackboard_summary: Dict[str, Any]) -> bool:
        """Check if blackboard evidence suggests blind SQL injection.

        Looks for indicators like "time_blind", "boolean_blind", "blind",
        "time-based", "boolean-based" in scenario hints, evidence details,
        and active routes.

        Requirements: 14.1
        """
        blind_keywords = {
            "time_blind", "boolean_blind", "blind", "time-based",
            "boolean-based", "blind_sqli", "blind_sql", "time based",
            "boolean based", "inferential",
        }

        # Check scenario hints
        scenario_hints = blackboard_summary.get("scenario_hints", [])
        for hint in scenario_hints:
            scenario_text = str(hint.get("scenario", "")).lower()
            route_text = str(hint.get("route", "")).lower()
            for keyword in blind_keywords:
                if keyword in scenario_text or keyword in route_text:
                    return True

        # Check top evidence
        top_evidence = blackboard_summary.get("top_evidence", [])
        for evidence in top_evidence:
            detail = str(evidence.get("detail", "")).lower()
            for keyword in blind_keywords:
                if keyword in detail:
                    return True

        # Check active routes for blind injection indicators
        active_routes = blackboard_summary.get("active_routes", [])
        for route in active_routes:
            route_lower = str(route).lower()
            for keyword in blind_keywords:
                if keyword in route_lower:
                    return True

        return False

    def _has_waf_indicators(self, blackboard_summary: Dict[str, Any]) -> bool:
        """Check if blackboard evidence shows WAF-blocked responses.

        Looks for indicators like "waf", "blocked", "403", "forbidden",
        "firewall", "mod_security" in evidence and scenario hints.

        Requirements: 14.2
        """
        waf_keywords = {
            "waf", "blocked", "403", "forbidden", "firewall",
            "mod_security", "modsecurity", "cloudflare", "akamai",
            "imperva", "web application firewall", "request blocked",
            "access denied",
        }

        # Check scenario hints
        scenario_hints = blackboard_summary.get("scenario_hints", [])
        for hint in scenario_hints:
            scenario_text = str(hint.get("scenario", "")).lower()
            for keyword in waf_keywords:
                if keyword in scenario_text:
                    return True

        # Check top evidence
        top_evidence = blackboard_summary.get("top_evidence", [])
        for evidence in top_evidence:
            detail = str(evidence.get("detail", "")).lower()
            for keyword in waf_keywords:
                if keyword in detail:
                    return True

        # Check active routes
        active_routes = blackboard_summary.get("active_routes", [])
        for route in active_routes:
            route_lower = str(route).lower()
            for keyword in waf_keywords:
                if keyword in route_lower:
                    return True

        return False


# ---------------------------------------------------------------------------
# Phase2Worker — Individual LLM Racing Thread
# ---------------------------------------------------------------------------


class Phase2Worker(threading.Thread):
    """Individual LLM worker thread for Phase 2 parallel racing.

    Executes a tool-calling loop: sends messages to LLM → LLM returns
    tool_calls → executes tools → feeds results back → repeats until
    a flag is found, cancellation is signaled, or budget is exhausted.

    Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 7.3, 7.4, 7.5,
                  8.2, 8.3, 8.4, 8.5, 9.2, 10.2, 11.2, 11.4, 11.6
    """

    def __init__(
        self,
        worker_id: str,
        strategy_hint: str,
        llm_client: "LLMClient",
        tool_router: "ToolRouter",
        session: "requests.Session",
        cancel_event: threading.Event,
        blackboard_summary: Dict[str, Any],
        flag_engine: "FlagEngine",
        target_origin: str,
        max_turns: int = 10,
        max_tokens: int = 8000,
        tool_timeout: float = 30.0,
        discovery_broadcast: Optional[DiscoveryBroadcast] = None,
        assignment: Optional[WorkerAssignment] = None,
    ) -> None:
        super().__init__(daemon=True)
        self.worker_id = worker_id
        self.strategy_hint = strategy_hint
        self.llm_client = llm_client
        self.tool_router = tool_router
        self.session = session
        self.cancel_event = cancel_event
        self.blackboard_summary = blackboard_summary
        self.flag_engine = flag_engine
        self.target_origin = target_origin
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.tool_timeout = tool_timeout
        self.discovery_broadcast = discovery_broadcast
        self.assignment = assignment

        # Internal state
        self._result = WorkerResult(
            worker_id=worker_id,
            strategy_hint=strategy_hint,
            success=False,
            route=assignment.route if assignment else None,
            variant=assignment.variant if assignment else None,
        )
        self._tokens_used = 0
        self._api_calls = 0
        self._turns_completed = 0

        # Task 4.6: Tool call parameter hash for duplicate detection
        self._tool_call_hashes: set = set()

        # Task 4.8: Stagnation detection
        self._stagnation_counter: int = 0
        self._known_endpoints: set = set()
        self._known_evidence: set = set()
        self._known_flags: set = set()

        # Task 5.6: Discovery broadcast read tracking
        self._last_broadcast_read_time: float = time.time()

        # Task 6.6: Internal reasoning log (parsed <plan>/<hypothesis> blocks)
        self._reasoning_log: List[str] = []

    @property
    def result(self) -> WorkerResult:
        """Access the worker's result after thread completion."""
        return self._result

    def run(self) -> None:
        """Execute tool-calling loop until flag, cancellation, or budget.

        This is the thread entry point. Builds the initial message context
        with strategy hint and blackboard summary, then enters the
        LLM → tool → feedback loop.

        Requirements: 6.1, 6.3, 8.3, 8.4, 9.2, 11.2
        """
        try:
            self._run_tool_calling_loop()
        except Exception as exc:
            log.error("Worker %s crashed: %s", self.worker_id, exc)
            self._result.error = f"worker_crash: {exc}"
        finally:
            # Finalize result
            self._result.turns_completed = self._turns_completed
            self._result.api_calls = self._api_calls
            self._result.tokens_used = self._tokens_used
            # Task 6.6: Copy reasoning log to result
            self._result.reasoning_log = list(self._reasoning_log)

    def _run_tool_calling_loop(self) -> None:
        """Core tool-calling loop implementation.

        Enhanced with:
        - Task 4.6/4.7: Duplicate tool call detection and direction hints
        - Task 4.8: Stagnation detection after 3 turns with no progress
        - Task 5.6: Discovery broadcast injection before each LLM call
        - Task 5.7: Auto-extract discoveries from tool results
        """
        # Build system prompt with strategy hint (Req 9.2)
        system_prompt = self._build_system_prompt()

        # Build initial messages
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": self._build_initial_user_message()},
        ]

        # Get tool definitions from the router
        tool_definitions = self.tool_router.definitions()

        for turn in range(self.max_turns):
            # Check cancellation before LLM call (Req 8.3)
            if self._check_cancelled():
                self._result.cancelled = True
                return

            # Check token budget (Req 11.2)
            if self._tokens_used >= self.max_tokens:
                self._result.error = "token_budget_exceeded"
                return

            # --- Task 6.1: Context compression when tokens exceed threshold ---
            messages = self._compact_messages(messages)

            # --- Task 5.6: Inject new discoveries from broadcast ---
            self._inject_broadcast_discoveries(messages)

            # --- Task 4.8: Inject stagnation warning if needed ---
            if self._stagnation_counter >= 3:
                messages.append({
                    "role": "user",
                    "content": (
                        "[STAGNATION WARNING] You have made 3 consecutive turns "
                        "without discovering new endpoints, evidence, or flag hints. "
                        "Change your approach: try a completely different attack vector, "
                        "explore different URL paths, or use different tool parameters."
                    ),
                })
                self._result.stagnation_warnings += 1
                self._stagnation_counter = 0  # Reset after warning
                log.debug(
                    "Worker %s: stagnation warning injected (total=%d)",
                    self.worker_id, self._result.stagnation_warnings,
                )

            # Make LLM API call (Req 6.1)
            try:
                response = self.llm_client.chat(
                    messages=messages,
                    tools=tool_definitions,
                    tool_choice="auto",
                    temperature=0.3,
                    max_tokens=min(1200, self.max_tokens - self._tokens_used),
                )
            except Exception as exc:
                log.warning("Worker %s LLM call failed: %s", self.worker_id, exc)
                self._result.error = f"llm_error: {exc}"
                return

            self._api_calls += 1
            self._turns_completed = turn + 1

            # Track token usage
            usage = response.get("usage", {})
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)
            self._tokens_used += prompt_tokens + completion_tokens

            # Check token budget after response (Req 11.2)
            if self._tokens_used >= self.max_tokens:
                self._result.error = "token_budget_exceeded"
                return

            # Process response
            tool_calls = response.get("tool_calls", [])
            content = response.get("content", "")

            # --- Task 6.6: Parse <plan>/<hypothesis> blocks from assistant content ---
            # --- Task 6.7: Parsed reasoning is stored but NOT fed back to messages ---
            if content:
                self._parse_reasoning_blocks(content)

            # Add assistant message to conversation
            assistant_msg: Dict[str, Any] = {"role": "assistant", "content": content}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            messages.append(assistant_msg)

            # If no tool calls, the LLM is done reasoning — check content for flags
            if not tool_calls:
                # Scan assistant content for flags
                if content:
                    candidates = self.flag_engine.scan(content)
                    if candidates:
                        flag_value = candidates[0].value
                        self._result.success = True
                        self._result.flag = flag_value
                        self._result.winning_tool_call = "content_scan"
                        self.cancel_event.set()  # Req 8.2
                        return
                # No tool calls and no flag — increment stagnation
                self._stagnation_counter += 1
                continue

            # Track whether this turn produced new discoveries (for stagnation)
            turn_found_new = False

            # Execute each tool call (Req 6.3)
            for tc in tool_calls:
                # Check cancellation before tool execution (Req 8.4)
                if self._check_cancelled():
                    self._result.cancelled = True
                    return

                tc_id = tc.get("id", "")
                func_info = tc.get("function", {})
                tool_name = func_info.get("name", "")
                arguments_str = func_info.get("arguments", "{}")

                # Parse arguments
                try:
                    arguments = json.loads(arguments_str) if isinstance(arguments_str, str) else arguments_str
                except (json.JSONDecodeError, TypeError):
                    # Malformed tool call
                    tool_result = "Invalid tool call format: could not parse arguments"
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": tool_result,
                    })
                    continue

                # --- Task 4.6/4.7: Duplicate tool call detection ---
                call_hash = self._compute_tool_call_hash(tool_name, arguments)
                if call_hash in self._tool_call_hashes:
                    # Duplicate detected — skip execution, inject hint
                    self._result.duplicate_calls_detected += 1
                    duplicate_msg = (
                        f"[DUPLICATE CALL SKIPPED] You've already tried "
                        f"{tool_name} with these exact parameters. "
                        f"Try a different approach or different parameters."
                    )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": duplicate_msg,
                    })
                    log.debug(
                        "Worker %s: duplicate tool call detected (%s), total=%d",
                        self.worker_id, tool_name, self._result.duplicate_calls_detected,
                    )
                    continue

                # Record this call hash
                self._tool_call_hashes.add(call_hash)

                # Execute tool with timeout and origin check (Req 6.6, 7.4, 7.5, 11.6)
                tool_result = self._execute_tool(tool_name, arguments)

                # --- Task 5.7: Auto-extract discoveries from tool result ---
                self._extract_and_publish_discoveries(tool_name, tool_result)

                # --- Task 6.8: Broadcast hypothesis on high-value discoveries ---
                self._broadcast_hypothesis_on_discovery(tool_name, tool_result)

                # --- Task 7.2-7.5: Dynamic tool unlocking based on tool results ---
                self._check_and_unlock_tools(tool_name, tool_result, tool_definitions)

                # --- Task 4.8: Check if this tool result has new info ---
                if self._has_new_discoveries(tool_result):
                    turn_found_new = True

                # Scan tool result for flags (Req 8.2)
                flag_found = self._scan_for_flag(tool_result)
                if flag_found:
                    self._result.success = True
                    self._result.flag = flag_found
                    self._result.winning_tool_call = f"{tool_name}({json.dumps(arguments)[:200]})"
                    self.cancel_event.set()  # Signal other workers (Req 8.2)
                    # Still add tool result to messages for completeness
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": tool_result if isinstance(tool_result, str) else json.dumps(tool_result),
                    })
                    return

                # Add tool result to messages for next LLM turn
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": tool_result if isinstance(tool_result, str) else json.dumps(tool_result),
                })

            # --- Task 4.8: Update stagnation counter ---
            if turn_found_new:
                self._stagnation_counter = 0
            else:
                self._stagnation_counter += 1

    def _check_cancelled(self) -> bool:
        """Check cancel_event; return True if should stop.

        Requirements: 6.4, 6.5, 8.3, 8.4, 8.5
        """
        return self.cancel_event.is_set()

    def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute tool via ToolRouter with timeout and origin check.

        Validates URLs against target_origin before execution, applies
        a timeout to the tool call, and returns the result as a string.

        Requirements: 6.3, 6.6, 7.4, 7.5, 11.4, 11.6
        """
        # URL origin validation for http_request and recon_scan (Req 7.4, 7.5, 11.4)
        if tool_name in ("http_request", "recon_scan"):
            url = arguments.get("url", "")
            if url and not self._validate_url(url):
                security_msg = (
                    f"Request blocked: URL '{url}' is outside target origin "
                    f"'{self.target_origin}'. Only requests to the target are allowed."
                )
                log.warning(
                    "Worker %s security violation: %s attempted URL %s",
                    self.worker_id, tool_name, url,
                )
                return security_msg

        # Execute with timeout (Req 6.6, 11.6)
        result_container: List[Dict[str, Any]] = []
        error_container: List[str] = []

        def _run_tool() -> None:
            try:
                result = self.tool_router.execute(tool_name, arguments)
                result_container.append(result)
            except Exception as exc:
                error_container.append(f"Tool execution failed: {exc}")

        tool_thread = threading.Thread(target=_run_tool, daemon=True)
        tool_thread.start()
        tool_thread.join(timeout=self.tool_timeout)

        if tool_thread.is_alive():
            # Tool timed out (Req 6.6, 11.6)
            log.warning(
                "Worker %s tool %s timed out after %.1fs",
                self.worker_id, tool_name, self.tool_timeout,
            )
            return f"Tool timed out after {self.tool_timeout}s"

        if error_container:
            return error_container[0]

        if result_container:
            result = result_container[0]
            # Convert dict result to raw string for summarization
            if isinstance(result, dict):
                raw_output = json.dumps(result, ensure_ascii=False, default=str)
            else:
                raw_output = str(result)

            # Use intelligent summarizer instead of crude truncation
            try:
                from autopnex.ctf.result_summarizer import summarize_tool_result
                return summarize_tool_result(tool_name, raw_output, max_chars=2000)
            except Exception as exc:
                # Fallback to old truncation if summarizer fails
                log.debug(
                    "Worker %s summarizer failed for tool %s, falling back: %s",
                    self.worker_id, tool_name, exc,
                )
                return raw_output[:8000]

        return "Tool returned no result"

    def _validate_url(self, url: str) -> bool:
        """Ensure URL is within target_origin.

        Compares the scheme + netloc of the given URL against the
        configured target_origin. Returns True if the URL is allowed.

        Requirements: 7.4, 7.5, 11.4
        """
        if not self.target_origin:
            # If no target origin configured, allow all (permissive fallback)
            return True

        try:
            parsed_target = urllib.parse.urlparse(self.target_origin)
            parsed_url = urllib.parse.urlparse(url)

            # Compare scheme + netloc (origin)
            target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
            url_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

            return url_origin.lower() == target_origin.lower()
        except Exception:
            # If parsing fails, reject the URL
            return False

    def _scan_for_flag(self, tool_result: str) -> Optional[str]:
        """Scan tool result text for valid flag patterns.

        Uses FlagEngine to detect flags in tool output.
        Returns the flag value if found, None otherwise.
        """
        if not tool_result:
            return None

        text = tool_result if isinstance(tool_result, str) else str(tool_result)
        candidates = self.flag_engine.scan(text)

        # Also try decode_and_scan for encoded flags
        if not candidates:
            candidates = self.flag_engine.decode_and_scan(text)

        if candidates:
            # Return the highest-confidence candidate
            return candidates[0].value

        return None

    def _build_system_prompt(self) -> str:
        """Build system prompt with strategy hint, exploit steps, and evidence.

        When a WorkerAssignment is available, includes:
        - The route's deterministic exploit_steps as guidance
        - Evidence summary from the scan result
        - Failed routes (routes with score <= 0.3)
        - Attempted payloads from probe results

        Requirements: 9.2, Task 3.7
        """
        parts = [
            "You are an expert CTF (Capture The Flag) web security solver. "
            "Your goal is to find the flag hidden in the target web application.\n\n"
            f"**Strategy Directive**: Focus on the following attack vector: {self.strategy_hint}\n\n"
        ]

        # --- Task 3.7: Inject assignment-specific context ---
        if self.assignment is not None:
            # Route and variant info
            parts.append(f"**Assigned Route**: {self.assignment.route}")
            if self.assignment.variant != "default":
                parts.append(f"**Variant**: {self.assignment.variant}")
            parts.append("")

            # Evidence summary from scan result
            if self.assignment.scan_result is not None:
                sr = self.assignment.scan_result
                parts.append("**Evidence Summary**:")
                parts.append(f"- Evidence score: {sr.evidence_score:.2f}")
                if sr.knowledge_boost > 0:
                    parts.append(f"- Knowledge boost: +{sr.knowledge_boost:.1f} (historical match)")
                if sr.endpoints_found:
                    parts.append(f"- Discovered endpoints: {', '.join(sr.endpoints_found[:5])}")
                if sr.scenario_hints:
                    parts.append(f"- Scenario hints: {'; '.join(sr.scenario_hints[:3])}")
                if sr.probe_results:
                    parts.append(f"- Probe results: {len(sr.probe_results)} probes executed")
                parts.append("")

            # Exploit steps as deterministic guidance
            if self.assignment.exploit_steps:
                parts.append("**Exploit Steps (deterministic guidance)**:")
                parts.append("Follow these steps in order. Fill in parameters based on target responses:")
                for i, step in enumerate(self.assignment.exploit_steps[:8], 1):
                    step_name = step.get("name", f"step_{i}")
                    step_desc = step.get("description", "")
                    step_method = step.get("method", "GET")
                    step_path = step.get("path", "/")
                    step_line = f"  {i}. [{step_method}] {step_path}"
                    if step_name:
                        step_line += f" — {step_name}"
                    if step_desc:
                        step_line += f": {step_desc}"
                    parts.append(step_line)
                parts.append("")

            # Failed routes context (routes that scored low)
            if self.assignment.scan_result is not None and self.blackboard_summary:
                # Provide context about what didn't work
                active_routes = self.blackboard_summary.get("active_routes", [])
                if active_routes:
                    failed = [r for r in active_routes if r != self.assignment.route]
                    if failed:
                        parts.append(f"**Other routes explored (lower priority)**: {', '.join(failed[:5])}")
                        parts.append("")

        # Standard instructions
        parts.append(
            "You have access to tools for making HTTP requests, running Python code, "
            "scanning for flags, and performing reconnaissance. Use them systematically "
            "to explore the target and exploit vulnerabilities.\n\n"
            "Rules:\n"
            "- Only make requests to the target application\n"
            "- Be methodical: gather information first, then exploit\n"
            "- When you find something that looks like a flag, use scan_flag to verify\n"
            "- Focus on your assigned strategy but adapt if you find clear evidence of another vector\n"
        )

        # --- Task 6.5: Controlled scratchpad instruction ---
        parts.append(
            "\nReasoning format:\n"
            "- When reasoning, use brief <plan> or <hypothesis> tags.\n"
            "- Do NOT write long explanations or chain-of-thought.\n"
            "- Example: <plan>Try SQLi on /login with admin' OR 1=1--</plan>\n"
            "- Example: <hypothesis>The /backup endpoint may expose source code</hypothesis>\n"
            "- Keep reasoning concise (1-2 sentences max per tag).\n"
        )

        return "\n".join(parts)

    def _build_initial_user_message(self) -> str:
        """Build the initial user message with blackboard context."""
        parts = ["Solve this CTF web challenge. Find the flag.\n"]

        if self.target_origin:
            parts.append(f"Target URL: {self.target_origin}\n")

        if self.blackboard_summary:
            # Include relevant Phase 1 findings
            summary = self.blackboard_summary
            if summary.get("tech_stack"):
                parts.append(f"Tech stack: {', '.join(summary['tech_stack'])}")
            if summary.get("key_endpoints"):
                endpoints_str = ", ".join(
                    ep.get("path", "") for ep in summary["key_endpoints"][:8]
                )
                parts.append(f"Known endpoints: {endpoints_str}")
            if summary.get("forms"):
                forms_str = ", ".join(
                    f.get("action", "") for f in summary["forms"][:5]
                )
                parts.append(f"Forms found: {forms_str}")
            if summary.get("active_routes"):
                parts.append(f"Active attack routes: {', '.join(summary['active_routes'][:5])}")
            if summary.get("top_evidence"):
                evidence_str = "; ".join(
                    e.get("detail", "")[:80] for e in summary["top_evidence"][:3]
                )
                parts.append(f"Key evidence: {evidence_str}")
            if summary.get("scenario_hints"):
                hints_str = "; ".join(
                    f"{h.get('route', '')}: {h.get('scenario', '')}"
                    for h in summary["scenario_hints"][:3]
                )
                parts.append(f"Scenario hints: {hints_str}")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Task 4.6: Duplicate tool call detection
    # ------------------------------------------------------------------

    def _compute_tool_call_hash(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Compute a deterministic hash of (tool_name, sorted arguments).

        Used to detect when the LLM is repeating the exact same tool call
        with the same parameters, indicating a loop.
        """
        # Normalize arguments by sorting keys recursively
        normalized = json.dumps(
            {"tool": tool_name, "args": arguments},
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Task 4.8: Stagnation detection helpers
    # ------------------------------------------------------------------

    def _has_new_discoveries(self, tool_result: str) -> bool:
        """Check if a tool result contains new endpoints, evidence, or flag hints.

        Scans the tool result for URL paths, credentials, SQL errors, and
        other indicators of progress. Returns True if something new was found.
        """
        if not tool_result:
            return False

        found_new = False

        # Check for new endpoints (URL paths)
        endpoint_patterns = re.findall(r'(?:href|action|src|url)[=:]\s*["\']?(/[^\s"\'<>]+)', tool_result, re.IGNORECASE)
        endpoint_patterns += re.findall(r'(?:GET|POST|PUT|DELETE)\s+(/[^\s"\'<>]+)', tool_result)
        for ep in endpoint_patterns:
            if ep not in self._known_endpoints:
                self._known_endpoints.add(ep)
                found_new = True

        # Check for evidence indicators (SQL errors, source code, credentials)
        evidence_indicators = [
            r'(?:mysql|sqlite|postgresql|oracle|mssql).*(?:error|syntax|warning)',
            r'(?:password|passwd|pwd|secret|token|api_key)\s*[=:]\s*\S+',
            r'(?:<?php|import\s+\w+|from\s+\w+\s+import|require\s*\()',
            r'(?:CREATE\s+TABLE|SELECT\s+\*|INSERT\s+INTO|DROP\s+TABLE)',
            r'flag\{[^}]+\}',
        ]
        for pattern in evidence_indicators:
            matches = re.findall(pattern, tool_result, re.IGNORECASE)
            for match in matches:
                match_key = match[:100]  # Truncate for set storage
                if match_key not in self._known_evidence:
                    self._known_evidence.add(match_key)
                    found_new = True

        # Check for flag hints
        flag_hints = re.findall(r'(?:flag|ctf|key)\s*[{=:]\s*\S+', tool_result, re.IGNORECASE)
        for hint in flag_hints:
            if hint not in self._known_flags:
                self._known_flags.add(hint)
                found_new = True

        return found_new

    # ------------------------------------------------------------------
    # Task 5.6: Discovery broadcast injection
    # ------------------------------------------------------------------

    def _inject_broadcast_discoveries(self, messages: List[Dict[str, Any]]) -> None:
        """Read new discoveries from DiscoveryBroadcast and inject as summary.

        Called before each LLM call to share cross-worker discoveries.
        Only injects if there are new discoveries since last read.
        """
        if self.discovery_broadcast is None:
            return

        new_discoveries = self.discovery_broadcast.get_since(self._last_broadcast_read_time)
        # Filter out discoveries from this worker (avoid echo)
        new_discoveries = [d for d in new_discoveries if d.worker_id != self.worker_id]

        if not new_discoveries:
            return

        # Update read timestamp
        self._last_broadcast_read_time = time.time()
        self._result.discoveries_received += len(new_discoveries)

        # Build a brief summary of new discoveries
        summary_parts = ["[CROSS-WORKER DISCOVERY] Other workers found:"]
        for d in new_discoveries[:5]:  # Limit to 5 most recent
            type_label = d.discovery_type.replace("_", " ").title()
            # Truncate content for injection
            content_preview = d.content[:200]
            summary_parts.append(f"- [{type_label}] {content_preview}")

        if len(new_discoveries) > 5:
            summary_parts.append(f"  ... and {len(new_discoveries) - 5} more discoveries")

        discovery_message = "\n".join(summary_parts)
        messages.append({"role": "user", "content": discovery_message})

        log.debug(
            "Worker %s: injected %d broadcast discoveries",
            self.worker_id, len(new_discoveries),
        )

    # ------------------------------------------------------------------
    # Task 5.7: Auto-extract discoveries from tool results
    # ------------------------------------------------------------------

    def _extract_and_publish_discoveries(self, tool_name: str, tool_result: str) -> None:
        """Scan tool result for key discoveries and publish to broadcast.

        Looks for:
        - Source code leaks (PHP, Python, JS patterns)
        - Credentials (passwords, tokens, API keys)
        - Database structure (CREATE TABLE, column names)
        - New endpoints (URL paths)
        - Flag hints (partial flags, flag-like patterns)
        """
        if self.discovery_broadcast is None or not tool_result:
            return

        # --- Source code detection ---
        source_patterns = [
            (r'<\?php[\s\S]{20,300}', "PHP source code"),
            (r'(?:import|from)\s+\w+[\s\S]{20,200}(?:def|class)\s+\w+', "Python source"),
            (r'(?:const|let|var|function)\s+\w+[\s\S]{20,200}', "JavaScript source"),
        ]
        for pattern, label in source_patterns:
            match = re.search(pattern, tool_result, re.IGNORECASE)
            if match:
                content = f"[{label} in {tool_name}] {match.group(0)[:500]}"
                if self.discovery_broadcast.publish(
                    self.worker_id, "source_code", content
                ):
                    self._result.discoveries_published += 1

        # --- Credential detection ---
        cred_patterns = [
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'<>]{3,50})',
            r'(?:api[_-]?key|secret[_-]?key|token)\s*[=:]\s*["\']?([^\s"\'<>]{8,100})',
            r'(?:username|user)\s*[=:]\s*["\']?([^\s"\'<>]{2,50})',
        ]
        for pattern in cred_patterns:
            matches = re.findall(pattern, tool_result, re.IGNORECASE)
            for match in matches[:3]:  # Limit per pattern
                content = f"[Credential found in {tool_name}] {match[:100]}"
                if self.discovery_broadcast.publish(
                    self.worker_id, "credential", content
                ):
                    self._result.discoveries_published += 1

        # --- Database structure detection ---
        db_patterns = [
            r'CREATE\s+TABLE\s+\w+\s*\([^)]{10,500}\)',
            r'(?:mysql|sqlite|postgresql).*(?:error|syntax).*(?:near|at)\s+["\']([^"\']+)',
            r'(?:column|field|table)\s+["\']?(\w+)["\']?\s+(?:does not exist|not found|unknown)',
        ]
        for pattern in db_patterns:
            match = re.search(pattern, tool_result, re.IGNORECASE)
            if match:
                content = f"[DB structure in {tool_name}] {match.group(0)[:300]}"
                if self.discovery_broadcast.publish(
                    self.worker_id, "db_structure", content
                ):
                    self._result.discoveries_published += 1

        # --- Endpoint discovery ---
        # Only publish truly interesting endpoints (not static assets)
        endpoint_matches = re.findall(
            r'(?:href|action|src|url)[=:]\s*["\']?(/(?:api|admin|login|upload|flag|secret|backup|debug|config|shell|cmd|exec)[^\s"\'<>]*)',
            tool_result,
            re.IGNORECASE,
        )
        for ep in endpoint_matches[:3]:
            content = f"[Endpoint in {tool_name}] {ep}"
            if self.discovery_broadcast.publish(
                self.worker_id, "endpoint", content
            ):
                self._result.discoveries_published += 1

        # --- Flag hint detection ---
        flag_hints = re.findall(r'flag\{[^}]*\}', tool_result, re.IGNORECASE)
        for hint in flag_hints[:2]:
            content = f"[Flag hint in {tool_name}] {hint}"
            if self.discovery_broadcast.publish(
                self.worker_id, "flag_hint", content
            ):
                self._result.discoveries_published += 1

    # ------------------------------------------------------------------
    # Task 6.1-6.3: Context compression
    # ------------------------------------------------------------------

    def _compact_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compress messages when estimated tokens exceed max_tokens * 0.75.

        Compression strategy (Task 6.2):
        - Preserve system prompt (messages[0])
        - Preserve current assignment context
        - Preserve last 6 messages (3 tool interactions = assistant + tool pairs)
        - From removed messages, extract key findings (endpoints, credentials,
          flags, errors) and merge into a <context_summary> user message (Task 6.3)

        Task 6.4: Writes compression stats to WorkerResult.

        Args:
            messages: Current conversation messages list.

        Returns:
            Possibly compressed messages list. Returns unchanged if below threshold.
        """
        # Estimate token count: ~4 chars per token
        estimated_tokens = sum(len(m.get("content", "") or "") // 4 for m in messages)

        threshold = int(self.max_tokens * 0.75)
        if estimated_tokens <= threshold:
            return messages

        # --- Compression triggered ---
        log.debug(
            "Worker %s: context compression triggered (estimated=%d, threshold=%d)",
            self.worker_id, estimated_tokens, threshold,
        )

        # Keep system prompt (always messages[0])
        system_prompt = messages[0] if messages else {"role": "system", "content": ""}

        # Keep last 6 messages (3 tool interactions = assistant + tool pairs)
        tail_count = min(6, len(messages) - 1)
        tail_messages = messages[-tail_count:] if tail_count > 0 else []

        # Messages to compress: everything between system prompt and tail
        middle_start = 1
        middle_end = len(messages) - tail_count
        middle_messages = messages[middle_start:middle_end] if middle_end > middle_start else []

        if not middle_messages:
            # Nothing to compress
            return messages

        # Extract key findings from middle messages (Task 6.3)
        context_summary = self._extract_key_findings(middle_messages)

        # Calculate discarded tokens
        discarded_tokens = sum(len(m.get("content", "") or "") // 4 for m in middle_messages)

        # Build compressed message list
        context_summary_msg = {
            "role": "user",
            "content": f"<context_summary>\n{context_summary}\n</context_summary>",
        }

        compressed = [system_prompt, context_summary_msg] + tail_messages

        # Task 6.4: Update compression stats in WorkerResult
        self._result.compression_count += 1
        self._result.estimated_discarded_tokens += discarded_tokens
        self._result.retained_messages = len(compressed)

        log.debug(
            "Worker %s: compressed %d messages → %d retained, ~%d tokens discarded",
            self.worker_id, len(messages), len(compressed), discarded_tokens,
        )

        return compressed

    def _extract_key_findings(self, messages: List[Dict[str, Any]]) -> str:
        """Extract key findings from a list of messages for context summary.

        Scans message content for:
        - Discovered endpoints/URLs
        - Credentials (passwords, tokens, keys)
        - Flag-related content (partial flags, flag hints)
        - SQL/code errors indicating vulnerabilities
        - Important HTTP status codes and responses

        Returns a concise summary string.
        """
        endpoints: set = set()
        credentials: List[str] = []
        flag_hints: List[str] = []
        errors: List[str] = []
        key_responses: List[str] = []

        for msg in messages:
            content = msg.get("content", "") or ""
            if not content:
                continue

            # Extract endpoints
            ep_matches = re.findall(
                r'(?:href|action|src|url|path)[=:]\s*["\']?(/[^\s"\'<>]{2,80})',
                content, re.IGNORECASE,
            )
            endpoints.update(ep_matches[:10])

            # Also extract from GET/POST patterns
            method_eps = re.findall(r'(?:GET|POST|PUT|DELETE)\s+(/[^\s"\'<>]{2,80})', content)
            endpoints.update(method_eps[:5])

            # Extract credentials
            cred_matches = re.findall(
                r'(?:password|passwd|pwd|secret|token|api_key|username|user)\s*[=:]\s*["\']?([^\s"\'<>]{2,60})',
                content, re.IGNORECASE,
            )
            for c in cred_matches[:5]:
                cred_entry = c[:60]
                if cred_entry not in credentials:
                    credentials.append(cred_entry)

            # Extract flag hints
            flag_matches = re.findall(r'flag\{[^}]*\}', content, re.IGNORECASE)
            for f in flag_matches:
                if f not in flag_hints:
                    flag_hints.append(f)

            # Also look for FLAG_FOUND markers
            if "FLAG_FOUND" in content or "flag{" in content.lower():
                # Preserve the surrounding context
                for line in content.split("\n"):
                    if "flag" in line.lower() and line.strip() not in flag_hints:
                        flag_hints.append(line.strip()[:200])
                        break

            # Extract error indicators
            error_matches = re.findall(
                r'(?:error|exception|traceback|syntax error|sql|warning)[:\s]+([^\n]{10,120})',
                content, re.IGNORECASE,
            )
            for e in error_matches[:3]:
                err_entry = e.strip()[:120]
                if err_entry not in errors:
                    errors.append(err_entry)

            # Extract key HTTP responses (status codes)
            status_matches = re.findall(r'(?:status[_\s]?code|HTTP/\d\.\d)\s*[=:]\s*(\d{3})', content)
            for s in status_matches[:3]:
                entry = f"HTTP {s}"
                if entry not in key_responses:
                    key_responses.append(entry)

        # Build summary
        parts: List[str] = []
        parts.append("Previous exploration summary:")

        if endpoints:
            sorted_eps = sorted(endpoints)[:15]
            parts.append(f"- Endpoints found: {', '.join(sorted_eps)}")

        if credentials:
            parts.append(f"- Credentials/secrets: {'; '.join(credentials[:5])}")

        if flag_hints:
            parts.append(f"- Flag-related: {'; '.join(flag_hints[:5])}")

        if errors:
            parts.append(f"- Errors/vulnerabilities: {'; '.join(errors[:5])}")

        if key_responses:
            parts.append(f"- HTTP responses: {', '.join(key_responses[:5])}")

        if not any([endpoints, credentials, flag_hints, errors, key_responses]):
            parts.append("- No significant findings extracted from previous turns.")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Task 6.6: Parse <plan>/<hypothesis> blocks from assistant content
    # ------------------------------------------------------------------

    def _parse_reasoning_blocks(self, content: str) -> None:
        """Parse <plan> and <hypothesis> blocks from assistant content.

        Extracts reasoning blocks and stores them in self._reasoning_log.
        These are NOT fed back into messages (Task 6.7) — they are stored
        only for debugging/analysis in WorkerResult.reasoning_log.
        """
        # Parse <plan>...</plan> blocks
        plan_matches = re.findall(r'<plan>(.*?)</plan>', content, re.DOTALL | re.IGNORECASE)
        for plan in plan_matches:
            entry = f"[plan] {plan.strip()[:300]}"
            self._reasoning_log.append(entry)

        # Parse <hypothesis>...</hypothesis> blocks
        hyp_matches = re.findall(r'<hypothesis>(.*?)</hypothesis>', content, re.DOTALL | re.IGNORECASE)
        for hyp in hyp_matches:
            entry = f"[hypothesis] {hyp.strip()[:300]}"
            self._reasoning_log.append(entry)

        if plan_matches or hyp_matches:
            log.debug(
                "Worker %s: parsed %d plan + %d hypothesis blocks (total log=%d)",
                self.worker_id, len(plan_matches), len(hyp_matches),
                len(self._reasoning_log),
            )

    # ------------------------------------------------------------------
    # Task 6.8: Broadcast hypothesis on high-value discoveries
    # ------------------------------------------------------------------

    def _broadcast_hypothesis_on_discovery(self, tool_name: str, tool_result: str) -> None:
        """When worker discovers source code, DB structure, credentials, or
        high-confidence flag hint, broadcast a brief hypothesis summary to
        DiscoveryBroadcast with type 'route_hint'.

        This supplements the existing _extract_and_publish_discoveries() by
        adding a higher-level hypothesis about what the discovery means for
        exploitation strategy.
        """
        if self.discovery_broadcast is None or not tool_result:
            return

        hypotheses: List[str] = []

        # Source code leak → hypothesis about exploitation path
        source_indicators = [
            (r'<\?php[\s\S]{20,}', "PHP source code leaked"),
            (r'(?:import|from)\s+\w+[\s\S]{20,}(?:def|class)\s+\w+', "Python source leaked"),
            (r'(?:const|let|var|function)\s+\w+[\s\S]{20,}', "JavaScript source leaked"),
        ]
        for pattern, label in source_indicators:
            if re.search(pattern, tool_result, re.IGNORECASE):
                # Extract a brief snippet for context
                match = re.search(pattern, tool_result, re.IGNORECASE)
                snippet = match.group(0)[:150] if match else ""
                hypotheses.append(
                    f"Source code discovered via {tool_name}: {label}. "
                    f"Snippet: {snippet}... "
                    f"May reveal hardcoded secrets, SQL queries, or flag logic."
                )
                break

        # DB structure → hypothesis about data extraction
        db_indicators = [
            r'CREATE\s+TABLE\s+(\w+)',
            r'(?:mysql|sqlite|postgresql).*(?:error|syntax)',
            r'(?:column|field|table)\s+["\']?(\w+)',
        ]
        for pattern in db_indicators:
            match = re.search(pattern, tool_result, re.IGNORECASE)
            if match:
                hypotheses.append(
                    f"Database structure exposed via {tool_name}: {match.group(0)[:100]}. "
                    f"Consider SQL injection to extract flag from database tables."
                )
                break

        # Credentials → hypothesis about authentication bypass
        cred_indicators = [
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'<>]{3,50})',
            r'(?:api[_-]?key|secret[_-]?key|token)\s*[=:]\s*["\']?([^\s"\'<>]{8,100})',
        ]
        for pattern in cred_indicators:
            match = re.search(pattern, tool_result, re.IGNORECASE)
            if match:
                hypotheses.append(
                    f"Credential discovered via {tool_name}: {match.group(0)[:80]}. "
                    f"Try using these credentials to access admin/protected endpoints."
                )
                break

        # High-confidence flag hint
        flag_pattern = re.search(r'flag\{[^}]+\}', tool_result, re.IGNORECASE)
        if flag_pattern:
            hypotheses.append(
                f"High-confidence flag hint via {tool_name}: {flag_pattern.group(0)[:100]}. "
                f"Verify with scan_flag tool immediately."
            )

        # Publish hypotheses as route_hint discoveries
        for hypothesis in hypotheses[:2]:  # Limit to 2 per tool call
            if self.discovery_broadcast.publish(
                self.worker_id, "route_hint", hypothesis
            ):
                self._result.discoveries_published += 1
                log.debug(
                    "Worker %s: broadcast route_hint hypothesis: %s",
                    self.worker_id, hypothesis[:80],
                )

    # ------------------------------------------------------------------
    # Task 7.2-7.6: Dynamic tool unlocking based on runtime tool results
    # ------------------------------------------------------------------

    def _check_and_unlock_tools(
        self, tool_name: str, tool_result: str, tool_definitions: List[Dict[str, Any]]
    ) -> None:
        """Check tool results for indicators that warrant unlocking specialist tools.

        Called after each tool execution. If a new tool should be unlocked,
        regenerates tool_definitions in-place so the next LLM call sees the
        updated tool set.

        Task 7.5: If tools need refresh at runtime, regenerate tool_definitions
        before next LLM call.
        Task 7.6: Record dynamic tool unlocks in WorkerResult and log.
        """
        if not tool_result:
            return

        unlocked_tools: List[str] = []

        # Task 7.2: Detect SQL errors / blind SQLi → unlock blind_sqli_extract
        if self._should_unlock_tool("blind_sqli_extract", tool_result):
            if self._try_unlock_tool("blind_sqli_extract"):
                unlocked_tools.append("blind_sqli_extract")

        # Task 7.3: Detect WAF / 403 / blocked → ensure waf_bypass_generate + prompt hint
        if self._should_unlock_tool("waf_bypass_generate", tool_result):
            if self._try_unlock_tool("waf_bypass_generate"):
                unlocked_tools.append("waf_bypass_generate")

        # Task 7.4: Detect LFI / file inclusion → unlock lfi_chain if supported
        if self._should_unlock_tool("lfi_chain", tool_result):
            if self._try_unlock_tool("lfi_chain"):
                unlocked_tools.append("lfi_chain")

        # Task 7.5: Regenerate tool_definitions if any tools were unlocked
        if unlocked_tools:
            new_definitions = self.tool_router.definitions()
            # Update tool_definitions in-place for the calling loop
            tool_definitions.clear()
            tool_definitions.extend(new_definitions)

            # Task 7.6: Record in WorkerResult and log
            self._result.tools_unlocked.extend(unlocked_tools)
            log.info(
                "Worker %s: dynamically unlocked tools: %s (total unlocked: %d)",
                self.worker_id,
                unlocked_tools,
                len(self._result.tools_unlocked),
            )

    def _should_unlock_tool(self, tool_name: str, tool_result: str) -> bool:
        """Determine if a specialist tool should be unlocked based on tool output.

        Task 7.2: SQL errors / blind SQLi indicators → blind_sqli_extract
        Task 7.3: WAF / 403 / blocked indicators → waf_bypass_generate
        Task 7.4: LFI / file inclusion indicators → lfi_chain

        Args:
            tool_name: The specialist tool to potentially unlock.
            tool_result: The raw output from the most recent tool execution.

        Returns:
            True if the tool_result contains indicators warranting the unlock.
        """
        result_lower = tool_result.lower()

        if tool_name == "blind_sqli_extract":
            # Task 7.2: Detect SQL errors or blind SQLi indicators
            sql_indicators = [
                "sql syntax",
                "mysql",
                "sqlite",
                "postgresql",
                "oracle",
                "mssql",
                "sql error",
                "syntax error",
                "unclosed quotation",
                "unterminated string",
                "you have an error in your sql",
                "warning: mysql",
                "sqlstate",
                "odbc",
                "jdbc",
                # Blind SQLi indicators
                "time-based blind",
                "boolean-based blind",
                "blind sql",
                "sleep(",
                "benchmark(",
                "waitfor delay",
                "pg_sleep",
                # Response-based indicators of injectable params
                "1=1",
                "or 1=1",
                "' or '",
            ]
            return any(indicator in result_lower for indicator in sql_indicators)

        elif tool_name == "waf_bypass_generate":
            # Task 7.3: Detect WAF / 403 / blocked responses
            waf_indicators = [
                "403 forbidden",
                "access denied",
                "request blocked",
                "waf",
                "web application firewall",
                "mod_security",
                "modsecurity",
                "cloudflare",
                "akamai",
                "imperva",
                "incapsula",
                "blocked by",
                "security rule",
                "not acceptable",
                "406 not acceptable",
                "request rejected",
                "forbidden",
                "your request has been blocked",
                "this request has been blocked",
            ]
            return any(indicator in result_lower for indicator in waf_indicators)

        elif tool_name == "lfi_chain":
            # Task 7.4: Detect LFI / file inclusion indicators
            lfi_indicators = [
                "include(",
                "require(",
                "include_once(",
                "require_once(",
                "file_get_contents(",
                "fopen(",
                "readfile(",
                "/etc/passwd",
                "root:x:0:0",
                "no such file or directory",
                "failed to open stream",
                "warning: include",
                "warning: require",
                "path traversal",
                "directory traversal",
                "../",
                "..\\",
                "php://filter",
                "php://input",
                "data://",
                "expect://",
                "file inclusion",
                "local file inclusion",
            ]
            return any(indicator in result_lower for indicator in lfi_indicators)

        return False

    def _try_unlock_tool(self, tool_name: str) -> bool:
        """Attempt to unlock a tool in the ToolRouter's enabled_tools set.

        Returns True if the tool was newly added (not already present).
        Returns False if the tool was already available or cannot be added.
        """
        try:
            enabled = getattr(self.tool_router, "enabled_tools", None)
            if enabled is None:
                return False

            if tool_name in enabled:
                # Already unlocked — no action needed
                return False

            # Add the tool to the enabled set
            enabled.add(tool_name)
            log.debug(
                "Worker %s: unlocked tool '%s' in ToolRouter",
                self.worker_id, tool_name,
            )
            return True
        except Exception as exc:
            log.debug(
                "Worker %s: failed to unlock tool '%s': %s",
                self.worker_id, tool_name, exc,
            )
            return False


def _default_runtime_config() -> "RuntimeConfig":
    """Create a minimal RuntimeConfig for fallback use."""
    from config.settings import RuntimeConfig
    return RuntimeConfig()
