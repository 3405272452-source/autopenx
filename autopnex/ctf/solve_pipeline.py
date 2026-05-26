"""CTFSolvePipeline — Phase upgrade decision and orchestration module.

Defines the core data models (PipelineConfig, SolveResult, UpgradeEvent) and
the CTFSolvePipeline class responsible for orchestrating Phase 1 → Phase 2 →
Phase 3 in sequence and producing a unified SolveResult.

Supports configurable thresholds per difficulty level and records all
phase transition events for benchmark reporting.

Architecture Note — Single Authority for Parallel AI Execution
==============================================================
``CTFSolvePipeline`` (this module) combined with ``Phase2Runner`` is the
**single canonical path** for parallel AI CTF solving. All new parallel
execution features — including ParallelRouteScan, dynamic worker assignment,
DiscoveryBroadcast, ExperienceWriter integration, and fast-track payloads —
MUST be implemented through this pipeline.

The legacy path ``CTFReActAgent._solve_multi_agent()`` in ``react_agent.py``
is retained only for backward compatibility. It should NOT receive new
feature development. Any parallel AI enhancement belongs here.

Ownership:
  - Phase 1 orchestration: CTFSolvePipeline.run() → MultiAgentOrchestrator
  - Phase 2 parallel workers: CTFSolvePipeline.run() → Phase2Runner
  - Phase 3 fallback: CTFSolvePipeline.run() → CTFReActAgent (single-agent)

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.1, 2.5, 4.5,
              11.1, 11.5, 15.1, 15.2, 15.3, 15.4, 15.5
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import requests
    from autopnex.ctf.attribution import Attribution
    from autopnex.ctf.flag_engine import FlagEngine
    from autopnex.ctf.web_state_blackboard import WebStateBlackboard
    from config.settings import RuntimeConfig

log = logging.getLogger("autopnex.ctf.solve_pipeline")


@dataclass
class PipelineConfig:
    """Configurable thresholds and budgets for the CTF solving pipeline.

    Controls phase transition thresholds, worker counts, timeouts, and
    budget limits for all three phases.

    All fields have sensible defaults — instantiating ``PipelineConfig()``
    with no arguments produces a fully functional configuration that is
    backward-compatible with previous versions.

    New Configuration Fields (Parallel AI Enhancement)
    --------------------------------------------------
    knowledge_path : Optional[str]
        Path to ctf_knowledge.json. Default: None (auto-detected).
    phase1_mode : str
        Phase 1 execution mode. One of "multi_agent", "parallel_scan",
        "hybrid". Default: "hybrid".
    parallel_scan_timeout : float
        Total timeout for parallel route scanning (seconds). Default: 30.0.
    parallel_scan_max_requests : int
        Maximum HTTP requests during parallel scan. Default: 100.
    phase2_dynamic_workers : bool
        Whether to dynamically assign workers based on scan results.
        Default: True.
    phase2_top_route_dual_worker : bool
        Whether the highest-scoring route gets two worker variants.
        Default: True.
    experience_write_enabled : bool
        Whether to write experience (solve/fail records) after pipeline
        completion. Default: True.
    fast_track_max_payloads : int
        Maximum fast-track payloads per route from experience. Default: 3.

    Backward Compatibility
    ----------------------
    All new fields have defaults that preserve existing behavior:
    - ``PipelineConfig()`` works identically to the pre-enhancement version
    - No new required parameters were introduced
    - Legacy fields (phase1_max_rounds_diff2, phase1_max_rounds_diff3,
      phase2_max_turns) are retained as deprecated aliases

    Attributes:
        stall_window: Consecutive rounds without evidence delta before
            declaring a stall (used by StallDetector).
        phase1_max_rounds: Safety cap on Phase 1 rounds regardless of
            stall detection.
        phase2_worker_count: Number of parallel LLM workers in Phase 2.
        phase2_max_turns_per_worker: Maximum turns each Phase 2 worker
            can execute.
        phase2_wall_clock_timeout_seconds: Wall-clock timeout for the
            entire Phase 2 racing period.
        max_tokens_per_worker: Per-worker token budget for Phase 2.
        phase3_max_iterations: Maximum iterations for Phase 3 ReAct agent.
        phase3_wall_clock_timeout_seconds: Wall-clock timeout for Phase 3.
        max_api_calls_per_challenge: Global API call budget across all phases.
        strategy_pool: List of strategy hints assigned to Phase 2 workers.
        hints_enabled: Whether hint injection is active during solving.
    """

    # Phase 1 (StallDetector) — keep short to hand off to LLM quickly
    stall_window: int = 2
    phase1_max_rounds: int = 5

    # Phase 2 — generous budget for LLM autonomous solving
    phase2_worker_count: int = 3
    phase2_max_turns_per_worker: int = 30
    phase2_wall_clock_timeout_seconds: float = 300.0
    max_tokens_per_worker: int = 1000000  # DeepSeek V4 Pro supports 1M context natively

    # Phase 3
    phase3_max_iterations: int = 30
    phase3_wall_clock_timeout_seconds: float = 180.0

    # Global budget
    max_api_calls_per_challenge: int = 100
    strategy_pool: List[str] = field(default_factory=lambda: [
        "sqli+auth", "lfi+ssti", "cmdi+upload", "ssrf+xxe", "deserialization+race"
    ])
    hints_enabled: bool = False

    # Knowledge base path (used by KnowledgeLearner / ExperienceWriter)
    knowledge_path: Optional[str] = None

    # Phase 1 mode: "multi_agent" (legacy), "parallel_scan", or "hybrid"
    # - multi_agent: only use MultiAgentOrchestrator (legacy behavior)
    # - parallel_scan: only use ParallelRouteScan
    # - hybrid: run ParallelRouteScan first for evidence, then MultiAgentOrchestrator
    phase1_mode: str = "hybrid"

    # Parallel scan configuration
    parallel_scan_timeout: float = 15.0
    parallel_scan_max_requests: int = 100

    # Phase 2 dynamic worker configuration
    phase2_dynamic_workers: bool = True
    phase2_top_route_dual_worker: bool = True

    # Experience / knowledge write-back
    experience_write_enabled: bool = True

    # Fast-track payload limit per route
    fast_track_max_payloads: int = 3

    # Fast-track direct solve: for simple challenges (source visible + single vuln),
    # skip Phase 0-1 and let one worker with large token budget solve directly.
    # Triggered when initial GET reveals source code with clear vulnerability.
    fast_track_direct_solve: bool = True
    fast_track_token_budget: int = 64000
    fast_track_max_turns: int = 25

    # --- Backward-compatible aliases (deprecated) ---
    # These map to the old PipelineConfig fields used by test_medium_ctf.py.
    # They are kept so existing code continues to work without modification.
    phase1_max_rounds_diff2: int = 15
    phase1_max_rounds_diff3: int = 10
    phase2_max_turns: int = 5


@dataclass
class SolveResult:
    """Unified result returned by CTFSolvePipeline.run().

    Contains success status, flag, attribution, timing metrics, and
    phase transition metadata for benchmark reporting.

    Attributes:
        success: Whether a valid flag was found.
        flag: The captured flag string, or None if not found.
        solving_phase: Which phase produced the flag ("phase1", "phase2",
            or "phase3").
        duration_ms: Total wall-clock time for the pipeline run.
        phase1_rounds: Number of rounds completed in Phase 1.
        phase2_turns: Total turns across all Phase 2 workers.
        phase3_iterations: Number of iterations completed in Phase 3.
        attribution: Metadata about which worker/model/strategy solved it.
        upgrade_events: Chronological list of phase transition events.
        error: Error description when no flag is found.
        phase1_action_log: Action log from Phase 1 (MultiAgentOrchestrator).
            Contains round-by-round decisions, tool calls, and evidence
            collected during deterministic route exploration. Used by
            ExperienceWriter to extract successful payloads and patterns.
    """

    success: bool
    flag: Optional[str] = None
    solving_phase: str = "phase1"
    duration_ms: float = 0.0
    phase1_rounds: int = 0
    phase2_turns: int = 0
    phase3_iterations: int = 0
    attribution: Optional[Attribution] = None
    upgrade_events: List[Dict[str, str]] = field(default_factory=list)
    error: Optional[str] = None
    phase1_action_log: List[Dict[str, Any]] = field(default_factory=list)
    phase1_scan_results: Optional[Dict[str, Any]] = None

    def to_json(self) -> str:
        """Serialize to JSON for benchmark reporting.

        Converts the SolveResult (including nested Attribution) to a
        JSON string. Attribution is serialized via its to_dict() method
        if present; otherwise it is set to null.

        The phase1_action_log is included as a summary (count only) to
        avoid excessively large JSON output. Full action_log is available
        via the field directly.

        Returns:
            A JSON string representation of this SolveResult.
        """
        data: Dict[str, Any] = {
            "success": self.success,
            "flag": self.flag,
            "solving_phase": self.solving_phase,
            "duration_ms": self.duration_ms,
            "phase1_rounds": self.phase1_rounds,
            "phase2_turns": self.phase2_turns,
            "phase3_iterations": self.phase3_iterations,
            "attribution": self.attribution.to_dict() if self.attribution else None,
            "upgrade_events": self.upgrade_events,
            "error": self.error,
            "phase1_action_log_count": len(self.phase1_action_log),
        }
        return json.dumps(data, indent=2)


@dataclass
class UpgradeEvent:
    """Records a phase transition event with timing and evidence context.

    Attributes:
        from_phase: The phase being left (e.g. "phase1").
        to_phase: The phase being entered (e.g. "phase2").
        reason: Human-readable reason for the upgrade.
        timestamp_ms: Wall-clock timestamp (ms since epoch) when the
            transition occurred.
        evidence_snapshot: Optional snapshot of blackboard metrics at
            the time of transition.
    """

    from_phase: str
    to_phase: str
    reason: str
    timestamp_ms: float
    evidence_snapshot: Optional[Dict[str, Any]] = None


class CTFSolvePipeline:
    """Single orchestration entry point for CTF solving.

    Executes Phase 1 → Phase 2 → Phase 3 in sequence and produces a
    unified SolveResult. This is the single authority for phase transition
    decisions and budget enforcement.

    **Architecture: Single Authority for Parallel AI Execution**

    This class, together with ``Phase2Runner``, is the ONLY sanctioned
    path for parallel AI CTF solving. The legacy method
    ``CTFReActAgent._solve_multi_agent()`` is deprecated and retained
    solely for backward compatibility — it must NOT receive new parallel
    execution features.

    All enhancements (ParallelRouteScan integration, dynamic worker
    assignment, DiscoveryBroadcast, ExperienceWriter, fast-track payloads,
    context compression, tool unlocking) are implemented exclusively
    through this pipeline to avoid dual-maintenance divergence.

    Phases:
        phase1 — MultiAgentOrchestrator (deterministic routes)
        phase2 — Parallel LLM Racing via Phase2Runner (N workers × M turns)
        phase3 — Sequential ReAct (remaining budget)

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 4.5, 11.1, 11.5
    """

    def __init__(
        self,
        config: PipelineConfig,
        target: Optional[str] = None,
        session: Optional[requests.Session] = None,
        blackboard: Optional[WebStateBlackboard] = None,
        flag_engine: Optional[FlagEngine] = None,
        runtime_config: Optional[RuntimeConfig] = None,
    ) -> None:
        self.config = config
        self.target = target
        self.session = session
        self.blackboard = blackboard
        self.flag_engine = flag_engine
        self.runtime_config = runtime_config
        self.phase_reached: str = "phase1"
        self._upgrade_events: List[Dict[str, str]] = []
        self._total_api_calls: int = 0

    def should_upgrade_to_phase2(self, rounds_elapsed: int, difficulty: int) -> bool:
        """Determine whether Phase 1 should upgrade to Phase 2.

        Args:
            rounds_elapsed: Number of rounds completed in Phase 1.
            difficulty: Challenge difficulty level (2 or 3).

        Returns:
            True if the stall threshold has been reached and Phase 2
            should be triggered.
        """
        threshold = (
            self.config.phase1_max_rounds_diff2
            if difficulty <= 2
            else self.config.phase1_max_rounds_diff3
        )
        return rounds_elapsed >= threshold

    def should_upgrade_to_phase3(self, turns_elapsed: int) -> bool:
        """Determine whether Phase 2 should upgrade to Phase 3.

        Args:
            turns_elapsed: Number of turns completed in Phase 2.

        Returns:
            True if the turn limit has been reached and Phase 3
            should be triggered.
        """
        return turns_elapsed >= self.config.phase2_max_turns

    def record_upgrade(self, from_phase: str, to_phase: str, reason: str) -> None:
        """Record a phase transition event.

        Updates the current phase and appends the transition to the
        event log for inclusion in benchmark reports.

        Args:
            from_phase: The phase being left (e.g. "phase1").
            to_phase: The phase being entered (e.g. "phase2").
            reason: Human-readable reason for the upgrade.
        """
        self.phase_reached = to_phase
        self._upgrade_events.append({
            "from": from_phase,
            "to": to_phase,
            "reason": reason,
        })

    @property
    def upgrade_events(self) -> List[Dict[str, str]]:
        """Read-only access to the list of recorded upgrade events."""
        return list(self._upgrade_events)

    def _is_llm_available(self) -> bool:
        """Check if any LLM provider has valid API keys configured.

        Inspects the runtime_config for a non-empty deepseek_api_key.
        Returns False if runtime_config is not set or no key is present.

        Requirements: 3.4
        """
        if self.runtime_config is None:
            return False
        return bool(getattr(self.runtime_config, "deepseek_api_key", ""))

    @staticmethod
    def _classify_llm_error(exc: Exception) -> Optional[str]:
        """Classify an exception as a known LLM error type.

        Detects rate-limit (HTTP 429), authentication (HTTP 401), and
        permission (HTTP 403) errors from the OpenAI SDK or from
        requests.HTTPError responses.

        Returns a short classification string if the error is a known
        LLM provider error, or None for unrecognized exceptions.

        Requirements: 3.2
        """
        # Check OpenAI SDK error types (openai >= 1.x)
        try:
            import openai

            if isinstance(exc, openai.RateLimitError):
                return "rate_limit_429"
            if isinstance(exc, openai.AuthenticationError):
                return "auth_error_401"
            if isinstance(exc, openai.PermissionDeniedError):
                return "permission_denied_403"
            # Generic API status error with status code
            if isinstance(exc, openai.APIStatusError):
                status = getattr(exc, "status_code", None)
                if status == 429:
                    return "rate_limit_429"
                if status == 401:
                    return "auth_error_401"
                if status == 403:
                    return "permission_denied_403"
        except ImportError:
            pass

        # Check requests.HTTPError (if Phase2Runner uses raw HTTP)
        try:
            import requests as _requests

            if isinstance(exc, _requests.HTTPError):
                resp = getattr(exc, "response", None)
                if resp is not None:
                    status = getattr(resp, "status_code", None)
                    if status == 429:
                        return "rate_limit_429"
                    if status == 401:
                        return "auth_error_401"
                    if status == 403:
                        return "permission_denied_403"
        except ImportError:
            pass

        # Check for LLMError wrapping status info
        from autopnex.orchestrator.llm_client import LLMError

        if isinstance(exc, LLMError):
            msg = str(exc).lower()
            if "429" in msg or "rate" in msg:
                return "rate_limit_429"
            if "401" in msg or "authentication" in msg or "unauthorized" in msg:
                return "auth_error_401"
            if "403" in msg or "permission" in msg or "forbidden" in msg:
                return "permission_denied_403"

        return None

    async def run(self) -> SolveResult:
        """Single entry point: Phase 0 → Phase 1 → Phase 2 → Phase 3.

        Orchestrates the full CTF solving pipeline:
          - Phase 0: Knowledge matching + target fingerprint collection
          - Phase 1: ParallelRouteScan (if hybrid/parallel_scan mode) and/or
                     MultiAgentOrchestrator (deterministic routes)
          - Phase 2: Parallel LLM Racing via Phase2Runner
          - Phase 3: Sequential ReAct fallback

        Returns a SolveResult with appropriate fields for each exit path.

        Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 4.5, 11.1, 11.5
        """
        import concurrent.futures

        from autopnex.ctf.multi_agent import MultiAgentOrchestrator
        from autopnex.ctf.stall_detector import StallDetector

        start_time = time.time()

        # ---------------------------------------------------------------
        # Fast-Track Direct Solve: For simple challenges where source code
        # is visible and contains a clear single vulnerability, skip the
        # entire Phase 0-1 pipeline and let one LLM worker solve directly
        # with a large token budget.
        # ---------------------------------------------------------------
        if self.config.fast_track_direct_solve and self._is_llm_available():
            fast_result = await self._try_fast_track_direct(start_time)
            if fast_result is not None:
                return fast_result

        # ---------------------------------------------------------------
        # Phase 0: Knowledge matching + target fingerprint collection
        # ---------------------------------------------------------------
        log.info("[progress_event] phase0_knowledge_match: starting")
        log.info("CTFSolvePipeline: starting Phase 0 (knowledge matching)")

        # Quick connectivity pre-check (3s timeout) to fail fast
        try:
            import requests as _req
            _req.head(self.target, timeout=3, allow_redirects=True)
        except Exception as _conn_err:
            log.warning("Target connectivity check failed (will continue): %s", _conn_err)

        self.knowledge_learner: Optional[Any] = None
        self.phase0_match: Optional[Dict[str, Any]] = None

        try:
            from autopnex.ctf.knowledge_learner import KnowledgeLearner

            knowledge_learner = KnowledgeLearner(
                knowledge_path=self.config.knowledge_path
            )
            self.knowledge_learner = knowledge_learner

            # Build a basic blackboard state for pattern matching
            blackboard_state: Dict[str, Any] = {
                "target_url": self.target or "",
                "tech_stack": [],
                "interesting_params": [],
                "top_evidence": [],
                "forms": [],
            }
            # If we already have a blackboard with state, use it
            if self.blackboard is not None and hasattr(self.blackboard, "state_summary"):
                try:
                    blackboard_state = self.blackboard.state_summary()
                except Exception:
                    pass

            match = knowledge_learner.match_pattern(blackboard_state)
            if match is not None:
                self.phase0_match = match
                log.info(
                    "[progress_event] phase0_knowledge_match: found route=%s scenario=%s",
                    match.get("route", "unknown"),
                    match.get("scenario", "unknown"),
                )
                log.info(
                    "Phase 0: knowledge match found — route=%s scenario=%s",
                    match.get("route", "unknown"),
                    match.get("scenario", "unknown"),
                )
            else:
                log.info("[progress_event] phase0_knowledge_match: no_match")
                log.info("Phase 0: no knowledge match found")
        except Exception as exc:
            # Phase 0 is non-fatal — failure should not block the pipeline
            log.warning("Phase 0 knowledge matching failed (non-fatal): %s", exc)

        # ---------------------------------------------------------------
        # Phase 0.5: Parallel Route Scan (if mode is "parallel_scan" or "hybrid")
        # ---------------------------------------------------------------
        scan_output: Optional[Any] = None

        if self.config.phase1_mode in ("parallel_scan", "hybrid"):
            log.info(
                "[progress_event] parallel_scan_start: mode=%s timeout=%.1fs max_requests=%d",
                self.config.phase1_mode,
                self.config.parallel_scan_timeout,
                self.config.parallel_scan_max_requests,
            )
            log.info(
                "CTFSolvePipeline: running ParallelRouteScan (mode=%s)",
                self.config.phase1_mode,
            )
            try:
                from autopnex.ctf.parallel_route_scan import ParallelRouteScan

                import requests as _req

                scan_session = self.session if self.session is not None else _req.Session()

                scan = ParallelRouteScan(
                    target_url=self.target or "",
                    session=scan_session,
                    knowledge_learner=self.knowledge_learner,
                    timeout=self.config.parallel_scan_timeout,
                    max_requests=self.config.parallel_scan_max_requests,
                )
                scan_output = scan.run()

                # --- Task 2.5: If flag found during scan, short-circuit return ---
                if scan_output.flag_found:
                    duration_ms = (time.time() - start_time) * 1000
                    from autopnex.ctf.attribution import Attribution as Attr

                    log.info(
                        "CTFSolvePipeline: flag found during parallel scan! "
                        "Short-circuit returning."
                    )
                    return SolveResult(
                        success=True,
                        flag=scan_output.flag_found,
                        solving_phase="phase1",
                        duration_ms=duration_ms,
                        phase1_rounds=0,
                        attribution=Attr(solving_phase="phase1"),
                        upgrade_events=self._upgrade_events,
                        phase1_scan_results={
                            "routes_scanned": len(scan_output.results),
                            "routes_above_threshold": scan_output.routes_above_threshold,
                            "total_requests": scan_output.total_requests_made,
                            "total_duration_ms": scan_output.total_duration_ms,
                            "knowledge_matches": scan_output.knowledge_matches,
                        },
                    )

                # Write scan results to blackboard
                if self.blackboard is not None:
                    scan.write_to_blackboard(self.blackboard, scan_output)

                # Capture main page source for LLM workers to analyze
                try:
                    import requests as _req
                    page_session = self.session if self.session else _req.Session()
                    page_resp = page_session.get(
                        self.target or "", timeout=8, allow_redirects=True
                    )
                    if page_resp.status_code == 200 and self.blackboard is not None:
                        self.blackboard.page_source = page_resp.text[:3000]
                        log.info("Captured page source (%d chars) for LLM workers", len(page_resp.text))
                except Exception as exc:
                    log.debug("Failed to capture page source: %s", exc)

                log.info(
                    "ParallelRouteScan complete: %d routes, %d above threshold, "
                    "%.1f ms, %d requests",
                    len(scan_output.results),
                    scan_output.routes_above_threshold,
                    scan_output.total_duration_ms,
                    scan_output.total_requests_made,
                )
                # --- Task 11.4: Phase 1 scan summary ---
                log.info(
                    "[progress_event] parallel_scan_finish: routes=%d above_threshold=%d "
                    "duration_ms=%.1f requests=%d knowledge_matches=%s",
                    len(scan_output.results),
                    scan_output.routes_above_threshold,
                    scan_output.total_duration_ms,
                    scan_output.total_requests_made,
                    scan_output.knowledge_matches,
                )
                # Output per-route scores for observability
                for sr in scan_output.results:
                    boost_status = "boosted" if getattr(sr, "knowledge_boost", 0) > 0 else "no_boost"
                    log.info(
                        "  [scan_route] route=%s score=%.3f duration_ms=%.1f "
                        "knowledge_boost=%.2f (%s)",
                        sr.route,
                        sr.evidence_score,
                        sr.probe_duration_ms,
                        getattr(sr, "knowledge_boost", 0.0),
                        boost_status,
                    )
            except Exception as exc:
                # Parallel scan failure is non-fatal (graceful degradation)
                log.warning(
                    "ParallelRouteScan failed (non-fatal, falling back): %s", exc
                )
                scan_output = None

        # Store scan_output for Phase 2 dynamic worker assignment
        self._scan_output = scan_output

        # ---------------------------------------------------------------
        # Phase 1: MultiAgentOrchestrator (deterministic routes)
        # ---------------------------------------------------------------
        log.info("CTFSolvePipeline: starting Phase 1 (deterministic routes)")
        self.phase_reached = "phase1"

        stall_detector = StallDetector(window=self.config.stall_window)

        # Build orchestrator
        orch = MultiAgentOrchestrator(
            target_url=self.target or "",
            max_rounds=self.config.phase1_max_rounds,
            session=self.session,
            hints_enabled=self.config.hints_enabled,
        )

        # Run Phase 1 in a thread (MultiAgentOrchestrator.run_loop is synchronous)
        phase1_rounds_used = 0
        phase1_flag: Optional[str] = None
        phase1_found = False

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    orch.run_loop, max_rounds=self.config.phase1_max_rounds
                )
                phase1_found, phase1_flag, _action_log = future.result(
                    timeout=self.config.phase2_wall_clock_timeout_seconds
                )
        except concurrent.futures.TimeoutError:
            log.warning("Phase 1 timed out")
            phase1_found, phase1_flag = False, None
            _action_log = []
        except Exception as exc:
            log.warning("Phase 1 error: %s", exc)
            phase1_found, phase1_flag = False, None
            _action_log = []

        # Count rounds from orchestrator state
        phase1_rounds_used = getattr(orch.coordinator, "current_round", 0)

        # --- Save Phase 1 action_log for experience accumulation ---
        # The action_log contains round-by-round decisions, tool calls,
        # and evidence collected during Phase 1. It is propagated to
        # SolveResult and made available for ExperienceWriter to extract
        # successful payloads and patterns.
        self.phase1_action_log: List[Dict[str, Any]] = _action_log

        # --- Write back orchestrator blackboard to pipeline blackboard ---
        # The MultiAgentOrchestrator maintains its own WebStateBlackboard
        # that accumulates evidence, endpoints, forms, params, cookies,
        # candidate flags, and scenario hints during Phase 1. We must
        # propagate this state back so Phase 2 and Phase 3 can access it.
        self.blackboard = orch.blackboard

        # Record stall detection from blackboard if available
        if self.blackboard is not None:
            stall_detector.record_round(self.blackboard)

        # --- Flag short-circuit: Phase 1 found a flag ---
        if phase1_found and phase1_flag:
            duration_ms = (time.time() - start_time) * 1000
            from autopnex.ctf.attribution import Attribution as Attr

            # Build scan results summary if available
            _scan_summary = None
            if scan_output is not None:
                _scan_summary = {
                    "routes_scanned": len(scan_output.results),
                    "routes_above_threshold": scan_output.routes_above_threshold,
                    "total_requests": scan_output.total_requests_made,
                    "total_duration_ms": scan_output.total_duration_ms,
                    "knowledge_matches": scan_output.knowledge_matches,
                }

            return SolveResult(
                success=True,
                flag=phase1_flag,
                solving_phase="phase1",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                attribution=Attr(solving_phase="phase1"),
                upgrade_events=self._upgrade_events,
                phase1_action_log=self.phase1_action_log,
                phase1_scan_results=_scan_summary,
            )

        # --- Phase 1 → Phase 2 transition decision ---
        # Use StallDetector as primary signal, max_rounds as safety fallback
        stall_reason = ""
        should_transition = False

        if self.blackboard is not None and stall_detector.is_stalled:
            should_transition = True
            stall_reason = stall_detector.reason
        elif phase1_rounds_used >= self.config.phase1_max_rounds:
            should_transition = True
            stall_reason = (
                f"Phase 1 safety cap reached ({phase1_rounds_used} rounds)"
            )
        else:
            # Phase 1 didn't find a flag and didn't stall — still transition
            should_transition = True
            stall_reason = "Phase 1 completed without flag"

        if not should_transition:
            # Should not happen, but handle gracefully
            duration_ms = (time.time() - start_time) * 1000
            return SolveResult(
                success=False,
                solving_phase="phase1",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                upgrade_events=self._upgrade_events,
                error="phase1_no_transition",
                phase1_action_log=self.phase1_action_log,
            )

        # --- Check LLM availability before Phase 2 ---
        if not self._is_llm_available():
            log.info("No LLM available — skipping Phase 2 and Phase 3")
            duration_ms = (time.time() - start_time) * 1000
            return SolveResult(
                success=False,
                solving_phase="phase1",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                upgrade_events=self._upgrade_events,
                error="llm_unavailable",
                phase1_action_log=self.phase1_action_log,
            )

        # ---------------------------------------------------------------
        # Phase 2: Parallel LLM Racing
        # ---------------------------------------------------------------
        self.record_upgrade("phase1", "phase2", stall_reason)
        log.info("CTFSolvePipeline: transitioning to Phase 2 — %s", stall_reason)
        log.info("[progress_event] phase2_assignment: workers=%d mode=%s",
                 self.config.phase2_worker_count,
                 "dynamic" if self.config.phase2_dynamic_workers else "static")

        # Budget check before Phase 2
        if self._total_api_calls >= self.config.max_api_calls_per_challenge:
            duration_ms = (time.time() - start_time) * 1000
            return SolveResult(
                success=False,
                solving_phase="phase2",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                upgrade_events=self._upgrade_events,
                error="budget_exhausted",
                phase1_action_log=self.phase1_action_log,
            )

        phase2_flag: Optional[str] = None
        phase2_turns = 0
        phase2_api_calls = 0
        phase2_llm_error: Optional[str] = None

        try:
            # Import Phase2Runner — may not be fully implemented yet (task 5.1)
            from autopnex.ctf.phase2_runner import Phase2Result

            try:
                from autopnex.ctf.phase2_runner import Phase2Runner

                runner = Phase2Runner(
                    config=self.config,
                    blackboard=self.blackboard,
                    session=self.session,
                    flag_engine=self.flag_engine,
                    runtime_config=self.runtime_config,
                    scan_output=self._scan_output,
                )
                phase2_result: Phase2Result = runner.run()
                phase2_turns = phase2_result.total_turns
                phase2_api_calls = phase2_result.total_api_calls
                self._total_api_calls += phase2_api_calls

                # --- Task 11.5: Phase 2 Worker summary ---
                if hasattr(phase2_result, "worker_results"):
                    for wr in phase2_result.worker_results:
                        log.info(
                            "[worker_summary] route=%s variant=%s turns=%d "
                            "api_calls=%d tokens=%d cancelled=%s broadcasts=%d",
                            getattr(wr, "route", "unknown"),
                            getattr(wr, "variant", "default"),
                            getattr(wr, "turns", 0),
                            getattr(wr, "api_calls", 0),
                            getattr(wr, "tokens_used", 0),
                            getattr(wr, "cancelled", False),
                            getattr(wr, "discovery_broadcast_count", 0),
                        )

                if phase2_result.success and phase2_result.flag:
                    phase2_flag = phase2_result.flag
            except ImportError:
                # Phase2Runner not yet implemented — skip Phase 2
                log.info("Phase2Runner not available — skipping Phase 2")
            except Exception as exc:
                # Handle rate-limit (429) and auth errors (401/403) specifically
                phase2_llm_error = self._classify_llm_error(exc)
                if phase2_llm_error:
                    log.warning(
                        "Phase 2 LLM error (%s): %s — proceeding to Phase 3",
                        phase2_llm_error, exc,
                    )
                else:
                    log.warning("Phase 2 error: %s", exc)

        except ImportError:
            log.info("phase2_runner module not available — skipping Phase 2")

        # --- Flag short-circuit: Phase 2 found a flag ---
        if phase2_flag:
            duration_ms = (time.time() - start_time) * 1000
            from autopnex.ctf.attribution import Attribution as Attr

            result = SolveResult(
                success=True,
                flag=phase2_flag,
                solving_phase="phase2",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                phase2_turns=phase2_turns,
                attribution=Attr(solving_phase="phase2"),
                upgrade_events=self._upgrade_events,
                phase1_action_log=self.phase1_action_log,
            )
            self._write_experience(result)
            return result

        # --- All LLM providers failed during Phase 2 initialization ---
        # If Phase 2 produced no turns and an LLM error was recorded,
        # all providers are unreachable. Return phase1 result per Req 3.3.
        if phase2_turns == 0 and phase2_llm_error:
            duration_ms = (time.time() - start_time) * 1000
            return SolveResult(
                success=False,
                solving_phase="phase1",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                upgrade_events=self._upgrade_events,
                error=f"llm_unavailable: all providers failed ({phase2_llm_error})",
                phase1_action_log=self.phase1_action_log,
            )

        # --- Budget check after Phase 2 ---
        if self._total_api_calls >= self.config.max_api_calls_per_challenge:
            duration_ms = (time.time() - start_time) * 1000
            return SolveResult(
                success=False,
                solving_phase="phase2",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                phase2_turns=phase2_turns,
                upgrade_events=self._upgrade_events,
                error="budget_exhausted",
                phase1_action_log=self.phase1_action_log,
            )

        # ---------------------------------------------------------------
        # Phase 3: Sequential ReAct (CTFReActAgent)
        # ---------------------------------------------------------------
        self.record_upgrade("phase2", "phase3", "Phase 2 exhausted budget without flag")
        log.info("CTFSolvePipeline: transitioning to Phase 3 (ReAct)")

        remaining_budget = (
            self.config.max_api_calls_per_challenge - self._total_api_calls
        )
        phase3_max_iters = min(
            self.config.phase3_max_iterations, remaining_budget
        )

        phase3_flag: Optional[str] = None
        phase3_iterations = 0

        try:
            from autopnex.ctf.react_agent import CTFReActAgent

            react_agent = CTFReActAgent(
                target=self.target or "",
                max_iterations=phase3_max_iters,
                timeout=int(self.config.phase3_wall_clock_timeout_seconds),
                runtime_config=self.runtime_config,
            )

            react_result = await react_agent.solve()
            phase3_iterations = react_result.get("iterations", phase3_max_iters)
            self._total_api_calls += phase3_iterations

            if react_result.get("success") and react_result.get("flag"):
                phase3_flag = react_result["flag"]

        except Exception as exc:
            log.warning("Phase 3 error: %s", exc)

        # --- Budget enforcement after Phase 3 ---
        if self._total_api_calls >= self.config.max_api_calls_per_challenge:
            if not phase3_flag:
                duration_ms = (time.time() - start_time) * 1000
                result = SolveResult(
                    success=False,
                    solving_phase="phase3",
                    duration_ms=duration_ms,
                    phase1_rounds=phase1_rounds_used,
                    phase2_turns=phase2_turns,
                    phase3_iterations=phase3_iterations,
                    upgrade_events=self._upgrade_events,
                    error="budget_exhausted",
                    phase1_action_log=self.phase1_action_log,
                )
                self._write_experience(result)
                return result

        # --- Phase 3 result ---
        duration_ms = (time.time() - start_time) * 1000

        if phase3_flag:
            from autopnex.ctf.attribution import Attribution as Attr

            result = SolveResult(
                success=True,
                flag=phase3_flag,
                solving_phase="phase3",
                duration_ms=duration_ms,
                phase1_rounds=phase1_rounds_used,
                phase2_turns=phase2_turns,
                phase3_iterations=phase3_iterations,
                attribution=Attr(solving_phase="phase3"),
                upgrade_events=self._upgrade_events,
                phase1_action_log=self.phase1_action_log,
            )
            self._write_experience(result)
            return result

        result = SolveResult(
            success=False,
            solving_phase="phase3",
            duration_ms=duration_ms,
            phase1_rounds=phase1_rounds_used,
            phase2_turns=phase2_turns,
            phase3_iterations=phase3_iterations,
            upgrade_events=self._upgrade_events,
            error="flag_not_found",
            phase1_action_log=self.phase1_action_log,
        )
        self._write_experience(result)
        return result

    async def _try_fast_track_direct(self, start_time: float) -> Optional[SolveResult]:
        """Fast-track: fetch page, detect simple vuln, let one LLM solve directly.

        For challenges where source code is visible and contains a clear
        single vulnerability (deserialization, command injection, SSTI, etc.),
        skip the entire multi-phase pipeline and give one LLM worker full
        autonomy with a large token budget.

        Returns SolveResult if solved, None if fast-track is not applicable.
        """
        import requests as _req

        try:
            # Step 1: Quick GET to fetch page source
            session = self.session or _req.Session()
            resp = session.get(self.target or "", timeout=10, allow_redirects=True)
            if resp.status_code != 200:
                return None

            page_source = resp.text
            if len(page_source) < 50:
                return None

            # Step 2: Detect if this is a "source visible + single vuln" challenge
            vuln_type = self._detect_simple_vuln(page_source)
            if vuln_type is None:
                return None

            log.info(
                "Fast-track direct solve triggered: detected %s vulnerability in page source",
                vuln_type,
            )

            # Step 3: Launch single LLM worker with large budget
            from autopnex.ctf.phase2_runner import Phase2Runner, Phase2Result, WorkerAssignment

            # Create a minimal config for the fast-track worker
            fast_config = PipelineConfig(
                phase2_worker_count=1,
                phase2_max_turns_per_worker=self.config.fast_track_max_turns,
                phase2_wall_clock_timeout_seconds=240.0,
                max_tokens_per_worker=self.config.fast_track_token_budget,
                phase2_dynamic_workers=False,
                strategy_pool=[vuln_type],
            )

            # Create a blackboard with the page source
            from autopnex.ctf.web_state_blackboard import WebStateBlackboard
            bb = WebStateBlackboard(target_url=self.target or "")
            bb.page_source = page_source

            runner = Phase2Runner(
                config=fast_config,
                blackboard=bb,
                session=session,
                flag_engine=self.flag_engine,
                runtime_config=self.runtime_config,
                scan_output=None,
            )

            phase2_result: Phase2Result = runner.run()

            if phase2_result.success and phase2_result.flag:
                duration_ms = (time.time() - start_time) * 1000
                from autopnex.ctf.attribution import Attribution as Attr

                result = SolveResult(
                    success=True,
                    flag=phase2_result.flag,
                    solving_phase="fast_track",
                    duration_ms=duration_ms,
                    phase2_turns=phase2_result.total_turns,
                    attribution=Attr(solving_phase="fast_track"),
                    upgrade_events=[{"from": "fast_track", "to": "done", "reason": vuln_type}],
                )
                self._write_experience(result)
                log.info("Fast-track solved in %.1fs! Flag: %s", duration_ms / 1000, phase2_result.flag)
                return result

            # Fast-track didn't solve it — fall through to normal pipeline
            log.info("Fast-track did not find flag (%d turns). Falling back to full pipeline.", phase2_result.total_turns)
            return None

        except Exception as exc:
            log.debug("Fast-track direct solve failed (non-fatal): %s", exc)
            return None

    def _detect_simple_vuln(self, page_source: str) -> Optional[str]:
        """Detect if page source reveals a simple, single vulnerability.

        Returns the vulnerability type string if detected, None otherwise.
        Only triggers for clear, unambiguous cases where the source code
        is directly visible and contains an obvious entry point.
        """
        source_lower = page_source.lower()

        # PHP deserialization: unserialize() with user input
        if "unserialize" in source_lower and ("$_post" in source_lower or "$_get" in source_lower or "$_request" in source_lower):
            return "deserialization"

        # Command injection: exec/system/passthru/shell_exec with user input
        for func in ("exec(", "system(", "passthru(", "shell_exec(", "popen("):
            if func in source_lower and ("$_" in source_lower):
                return "cmdi"

        # SSTI: render/template with user input
        if ("render" in source_lower or "template" in source_lower) and ("{{" in page_source or "{%" in page_source):
            return "ssti"

        # eval() with user input
        if "eval(" in source_lower and "$_" in source_lower:
            return "cmdi"

        # include/require with user input (LFI)
        for func in ("include(", "require(", "include_once(", "require_once("):
            if func in source_lower and "$_" in source_lower:
                return "lfi"

        return None

    def _write_experience(self, result: SolveResult) -> None:
        """Record solve/failure experience via ExperienceWriter.

        Called at the end of the pipeline run. Wraps all operations in
        try/except so that experience writing failures never affect the
        solve result.

        Requirements: REQ-3.1, REQ-3.3
        """
        if not self.config.experience_write_enabled:
            log.info("[progress_event] experience_write: disabled")
            return

        log.info("[progress_event] experience_write: starting (success=%s)", result.success)

        try:
            from autopnex.ctf.experience_writer import (
                ExperienceWriter,
                FailContext,
                SolveContext,
            )

            writer = ExperienceWriter(knowledge_path=self.config.knowledge_path)

            if result.success and result.flag:
                # Determine winning route from attribution or scan output
                winning_route = "unknown"
                scenario = "unknown"
                if result.attribution is not None:
                    winning_route = getattr(result.attribution, "route", "unknown") or "unknown"
                    scenario = getattr(result.attribution, "scenario", "unknown") or "unknown"

                # Build blackboard state snapshot
                blackboard_state: Optional[Dict[str, Any]] = None
                if self.blackboard is not None and hasattr(self.blackboard, "state_summary"):
                    try:
                        blackboard_state = self.blackboard.state_summary()
                    except Exception:
                        pass

                ctx = SolveContext(
                    target_url=self.target or "",
                    flag=result.flag,
                    winning_route=winning_route,
                    scenario=scenario,
                    action_log=result.phase1_action_log,
                    blackboard_state=blackboard_state,
                    duration_ms=result.duration_ms,
                )
                writer.record_solve(ctx)
                log.info(
                    "ExperienceWriter: recorded successful solve (route=%s)",
                    winning_route,
                )
            else:
                # Determine failure reason from the error field
                failure_reason = "timeout"
                error = result.error or ""
                if "budget_exhausted" in error:
                    failure_reason = "timeout"
                elif "llm_unavailable" in error:
                    failure_reason = "llm_unavailable"
                elif "waf" in error.lower() or "blocked" in error.lower():
                    failure_reason = "waf_blocked"
                elif "param" in error.lower():
                    failure_reason = "param_error"
                elif "route" in error.lower() or "invalid" in error.lower():
                    failure_reason = "route_invalid"

                # Determine which route was attempted
                route = "unknown"
                if self._scan_output is not None and hasattr(self._scan_output, "results"):
                    results = self._scan_output.results
                    if results:
                        route = results[0].route

                ctx = FailContext(
                    target_url=self.target or "",
                    route=route,
                    failure_reason=failure_reason,
                    action_log=result.phase1_action_log,
                    duration_ms=result.duration_ms,
                )
                writer.record_failure(ctx)
                log.info(
                    "ExperienceWriter: recorded failure (route=%s, reason=%s)",
                    route,
                    failure_reason,
                )
        except Exception as exc:
            # Experience writing failure must NEVER affect the solve result
            log.warning("ExperienceWriter failed (non-fatal): %s", exc)
