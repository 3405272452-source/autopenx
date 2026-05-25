"""Experience dual-write module — records solve/failure experiences.

After each CTF challenge attempt, ExperienceWriter records the outcome
into the unified knowledge base (ctf_knowledge.json).  It performs a
"dual write":

  1. AI knowledge (via KnowledgeLearner.record_success) — patterns,
     fingerprints, and scenario matching for future challenges.
  2. State machine config — route weights, fast payloads, and
     fingerprint→route mappings for deterministic priority adjustment.

All operations are wrapped in try/except for graceful degradation:
a failure in experience writing must NEVER block the main solve flow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from autopnex.ctf.knowledge_schema import load_knowledge, save_knowledge

log = logging.getLogger("autopnex.ctf.experience_writer")


# ---------------------------------------------------------------------------
# Context dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SolveContext:
    """Context for a successful solve — passed to ExperienceWriter.record_solve().

    Attributes:
        target_url: The target URL that was solved.
        flag: The captured flag value.
        winning_route: The route that found the flag (e.g. "sqli", "ssti").
        scenario: The specific scenario within the route (e.g. "login_bypass").
        action_log: Full action log from the multi-agent/worker loop.
        blackboard_state: The blackboard state_summary() dict at solve time.
        winning_tool_call: The specific tool call that found the flag.
        fingerprint: Target fingerprint/tech stack identifier.
        duration_ms: Total solve duration in milliseconds.
    """

    target_url: str
    flag: str
    winning_route: str
    scenario: str
    action_log: List[Dict[str, Any]]
    blackboard_state: Optional[Dict[str, Any]] = None
    winning_tool_call: Optional[Dict[str, Any]] = None
    fingerprint: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class FailContext:
    """Context for a failed attempt — passed to ExperienceWriter.record_failure().

    Attributes:
        target_url: The target URL that was attempted.
        route: The route that was tried.
        failure_reason: One of: waf_blocked, param_error, route_invalid,
            timeout, llm_unavailable.
        action_log: Action log from the failed attempt.
        duration_ms: Duration of the failed attempt in milliseconds.
    """

    target_url: str
    route: str
    failure_reason: str
    action_log: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# ExperienceWriter
# ---------------------------------------------------------------------------


class ExperienceWriter:
    """Dual-write experience recorder for CTF solves and failures.

    Records outcomes into the unified knowledge base schema, updating:
      - solve_history (via KnowledgeLearner)
      - route_weights (dynamic priority adjustment)
      - fast_payloads (successful payload templates for fast-track)
      - fingerprint_route_map (target fingerprint → successful routes)

    All operations are wrapped in try/except — failures in experience
    writing never propagate to the caller.
    """

    def __init__(self, knowledge_path: Optional[str] = None):
        """Initialize the ExperienceWriter.

        Args:
            knowledge_path: Path to the knowledge JSON file.
                If None, uses the default project-root location.
                If the file doesn't exist, a new one will be created
                on first write.
        """
        if knowledge_path is not None:
            self._knowledge_path: Optional[Path] = Path(knowledge_path)
        else:
            self._knowledge_path = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_solve(self, ctx: SolveContext) -> None:
        """Record a successful solve into the knowledge base.

        Performs dual-write:
          1. Updates route_weights (winning route gets a boost)
          2. Appends winning payload to fast_payloads
          3. Records fingerprint→route mapping

        Note: The AI knowledge write (KnowledgeLearner.record_success)
        is expected to be called separately by the pipeline, since
        KnowledgeLearner has its own state. This method handles the
        state-machine-config side of the dual write.

        Args:
            ctx: SolveContext with all details of the successful solve.
        """
        try:
            self._update_route_weights(ctx)
        except Exception as exc:
            log.warning("Failed to update route weights: %s", exc)

        try:
            self._append_winning_payload(ctx)
        except Exception as exc:
            log.warning("Failed to append winning payload: %s", exc)

        try:
            self._record_fingerprint_mapping(ctx)
        except Exception as exc:
            log.warning("Failed to record fingerprint mapping: %s", exc)

        log.info(
            "Experience recorded for solve: route=%s target=%s duration=%.0fms",
            ctx.winning_route,
            ctx.target_url,
            ctx.duration_ms,
        )

    def record_failure(self, ctx: FailContext) -> None:
        """Record a failed attempt — penalizes the route weight.

        Args:
            ctx: FailContext with details of the failed attempt.
        """
        try:
            self._penalize_route(ctx.route, ctx.failure_reason)
        except Exception as exc:
            log.warning("Failed to penalize route %s: %s", ctx.route, exc)

        log.info(
            "Experience recorded for failure: route=%s reason=%s target=%s",
            ctx.route,
            ctx.failure_reason,
            ctx.target_url,
        )

    # ------------------------------------------------------------------
    # Internal methods (skeleton — full implementation in tasks 8.2-8.9)
    # ------------------------------------------------------------------

    def _update_route_weights(self, ctx: SolveContext) -> None:
        """Update route_weights in the knowledge base after a successful solve.

        Winning route gets +0.1 weight (capped at 1.0).
        """
        knowledge = load_knowledge(self._knowledge_path)
        weights = knowledge.setdefault("route_weights", {})

        route = ctx.winning_route
        current = weights.get(route, 0.5)
        weights[route] = min(1.0, current + 0.1)

        save_knowledge(knowledge, self._knowledge_path)

    def _append_winning_payload(self, ctx: SolveContext) -> None:
        """Extract and store the winning payload template for fast-track reuse.

        Extracts the payload from winning_tool_call or the last successful
        HTTP action in action_log, then stores it as a template (without
        the full target URL) in fast_payloads[route].
        """
        knowledge = load_knowledge(self._knowledge_path)
        fast_payloads = knowledge.setdefault("fast_payloads", {})
        route_payloads = fast_payloads.setdefault(ctx.winning_route, [])

        # Extract payload template from winning tool call or action log
        payload = self._extract_payload_template(ctx)
        if payload and payload not in route_payloads:
            route_payloads.insert(0, payload)
            # Keep at most 20 fast payloads per route
            fast_payloads[ctx.winning_route] = route_payloads[:20]

        save_knowledge(knowledge, self._knowledge_path)

    def _record_fingerprint_mapping(self, ctx: SolveContext) -> None:
        """Record the mapping from target fingerprint to successful route.

        This allows future challenges with the same fingerprint/tech stack
        to skip the scan phase and go directly to the known-good route.
        """
        if not ctx.fingerprint:
            return

        knowledge = load_knowledge(self._knowledge_path)
        fp_map = knowledge.setdefault("fingerprint_route_map", {})

        routes = fp_map.setdefault(ctx.fingerprint, [])
        if ctx.winning_route not in routes:
            routes.append(ctx.winning_route)
            # Keep at most 5 routes per fingerprint
            fp_map[ctx.fingerprint] = routes[:5]

        save_knowledge(knowledge, self._knowledge_path)

    def _penalize_route(self, route: str, reason: str) -> None:
        """Decrease route weight based on failure reason.

        Penalty amounts:
          - waf_blocked:    -0.05 (might just need a different payload)
          - param_error:    -0.03 (minor — might just be wrong param name)
          - route_invalid:  -0.15 (heavy — route doesn't apply to target)
          - timeout:        -0.02 (almost no penalty — transient issue)
          - llm_unavailable: -0.01 (no penalty — not the route's fault)
        """
        knowledge = load_knowledge(self._knowledge_path)
        weights = knowledge.setdefault("route_weights", {})

        current = weights.get(route, 0.5)
        penalty = {
            "waf_blocked": 0.05,
            "param_error": 0.03,
            "route_invalid": 0.15,
            "timeout": 0.02,
            "llm_unavailable": 0.01,
        }.get(reason, 0.05)

        weights[route] = max(0.0, current - penalty)
        save_knowledge(knowledge, self._knowledge_path)

    # ------------------------------------------------------------------
    # Payload extraction helper
    # ------------------------------------------------------------------

    def _extract_payload_template(self, ctx: SolveContext) -> Optional[Dict[str, Any]]:
        """Extract a reusable payload template from the solve context.

        Tries winning_tool_call first, then falls back to scanning
        action_log for the last HTTP request that preceded flag discovery.

        Returns a template dict with: method, path, params, data, headers.
        Returns None if no usable payload can be extracted.
        """
        # Try winning_tool_call first
        if ctx.winning_tool_call:
            template = self._tool_call_to_template(ctx.winning_tool_call)
            if template:
                return template

        # Fallback: scan action_log for last HTTP action
        if ctx.action_log:
            for entry in reversed(ctx.action_log):
                if isinstance(entry, dict) and entry.get("tool") in (
                    "http_request",
                    "curl_request",
                    "web_request",
                ):
                    template = self._tool_call_to_template(entry)
                    if template:
                        return template

        return None

    def _tool_call_to_template(self, tool_call: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert a tool call dict into a reusable payload template.

        Strips the full target URL, keeping only path, method, params,
        data, and headers.
        """
        try:
            args = tool_call.get("arguments") or tool_call.get("params") or tool_call
            # Extract path from URL if present
            url = args.get("url", "")
            path = "/"
            if url:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"

            template: Dict[str, Any] = {
                "method": args.get("method", "GET").upper(),
                "path": path,
            }

            # Optional fields — only include if present
            if args.get("params"):
                template["params"] = args["params"]
            if args.get("data") or args.get("body"):
                template["data"] = args.get("data") or args.get("body")
            if args.get("headers"):
                template["headers"] = args["headers"]

            return template
        except Exception:
            return None
