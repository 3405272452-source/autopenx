"""M4: Multi-Agent Collaboration for Web CTF.

Architecture (per roadmap 8.2):
  CoordinatorAgent  — route selection, budget allocation, stop/no-stop decisions
  ReconAgent        — deterministic enumeration (minimal LLM calls)
  ExploitAgent      — runs RouteStateMachines, constructs payloads
  CriticAgent       — hypothesis refutation, repeat detection, switch suggestions

Protocol:
  All agents read/write WebStateBlackboard.
  All agent outputs are structured JSON, never prose.
  Coordinator combines route scores + budget + fuse state for decisions.
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from .web_state_blackboard import WebStateBlackboard, EvidenceCard, AttemptRecord
from .route_cards import RouteCard, ROUTE_CARDS, get_route_card
from .route_state_machine import (
    RouteStateMachine, MACHINE_REGISTRY, create_machine, run_route, RouteResult,
)
from .js_analyzer import JSAnalyzer

log = logging.getLogger("autopnex.ctf.multi_agent")


# ---------------------------------------------------------------------------
# Structured agent output
# ---------------------------------------------------------------------------

@dataclass
class AgentDecision:
    """Standardized agent output format."""
    agent: str
    route: str
    hypothesis: str
    confidence: float  # 0.0 - 1.0
    supporting_evidence: List[str] = field(default_factory=list)
    next_action: Dict[str, Any] = field(default_factory=dict)
    stop_if: List[str] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "route": self.route,
            "hypothesis": self.hypothesis,
            "confidence": self.confidence,
            "supporting_evidence": self.supporting_evidence,
            "next_action": self.next_action,
            "stop_if": self.stop_if,
            "reasoning": self.reasoning,
        }


# ---------------------------------------------------------------------------
# Base agent
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    """Abstract base for all specialist agents."""

    agent_name: str = "base"

    def __init__(self, blackboard: WebStateBlackboard, session: Optional[requests.Session] = None):
        self.blackboard = blackboard
        self.session = session or requests.Session()
        self._last_decision: Optional[AgentDecision] = None

    @abstractmethod
    def decide(self) -> AgentDecision:
        """Produce a structured decision based on blackboard state."""
        ...

    def execute(self, decision: AgentDecision) -> Dict[str, Any]:
        """Execute the agent's next action. Returns result dict."""
        if not decision.next_action:
            return {"error": "No action specified"}
        return {"status": "executed", "agent": self.agent_name, "route": decision.route}


# ---------------------------------------------------------------------------
# CoordinatorAgent
# ---------------------------------------------------------------------------

class CoordinatorAgent(BaseAgent):
    """Central coordinator — reads blackboard, selects route, allocates budget.

    Decision logic:
      1. Check for flag candidates — if high confidence, verify and stop
      2. Check fuse state — if too many failures, force route switch
      3. Score each route based on evidence + past attempts
      4. Select highest-ROI route with remaining budget
      5. Allocate LLM call budget to specialist agents
    """

    agent_name = "coordinator"

    # Route priority: higher = try first
    ROUTE_PRIORITY = {
        "source_leak": 10,  # Always first — highest ROI
        "ssti": 9,          # Strong signal, short chain
        "cmdi": 8,          # Direct flag read
        "lfi": 8,           # Direct flag read
        "sqli": 7,          # Common, scriptable
        "graphql": 7,       # Deterministic POST JSON
        "jwt": 7,           # Deterministic alg=none + weak-key brute force
        "upload": 7,        # Deterministic 2-step + multi-variant payloads
        "websocket": 8,     # Deterministic param-based bypass (direct flag)
        "xss": 8,           # Admin bot chain, deterministic direct flag
        "ssrf": 7,          # Deterministic file:// + metadata probes
        "php_pop": 7,       # Cookie/phar probes are cheap
        "idor": 7,          # Path-based id enumeration is cheap
        "recon": 5,
    }

    def __init__(self, blackboard: WebStateBlackboard, session=None,
                 max_rounds: int = 15, max_repeats_per_route: int = 3):
        super().__init__(blackboard, session)
        self.max_rounds = max_rounds
        self.max_repeats_per_route = max_repeats_per_route
        self.route_attempts: Dict[str, int] = {}   # route -> attempt count
        self.route_failures: Dict[str, int] = {}    # route -> consecutive failures
        self.current_round: int = 0
        self.budget_remaining: int = max_rounds

    def decide(self) -> AgentDecision:
        self.current_round += 1

        # 1. Check for verified flags
        flags = self.blackboard.candidate_flags
        high_conf_flags = [f for f in flags if f.confidence >= 0.8]
        if high_conf_flags:
            return AgentDecision(
                agent=self.agent_name,
                route="flag_verify",
                hypothesis=f"Found high-confidence flag: {high_conf_flags[0].value}",
                confidence=0.95,
                supporting_evidence=[f"Flag candidate: {f.value}" for f in high_conf_flags],
                next_action={"action": "stop", "reason": "flag_found"},
                reasoning="High-confidence flag found — stopping",
            )

        # 2. Check blockers
        if self.blackboard.blockers:
            return AgentDecision(
                agent=self.agent_name,
                route="unblock",
                hypothesis=f"Blocked: {self.blackboard.blockers[0]}",
                confidence=0.3,
                next_action={"action": "delegate", "to": "recon", "task": "resolve_blocker"},
                reasoning="Blocker detected — delegating to ReconAgent",
            )

        # 3. If no endpoints discovered yet, start with recon
        state = self.blackboard.state_summary()
        if state.get("endpoint_count", 0) == 0:
            return AgentDecision(
                agent=self.agent_name,
                route="recon",
                hypothesis="No endpoints discovered — need recon first",
                confidence=0.9,
                next_action={"action": "delegate", "to": "recon", "task": "full_recon"},
                reasoning="No endpoints — starting reconnaissance",
            )

        # 4. Score available routes
        scored_routes = self._score_routes()
        if not scored_routes:
            return AgentDecision(
                agent=self.agent_name,
                route="recon",
                hypothesis="Insufficient information — need recon",
                confidence=0.3,
                next_action={"action": "delegate", "to": "recon", "task": "full_recon"},
                reasoning="No routes scored — starting reconnaissance",
            )

        # 5. Select best route
        best_route, best_score = scored_routes[0]

        # Check if we should switch from current route
        if best_route in self.route_failures and self.route_failures[best_route] >= 3:
            # Force switch to next best
            for route, score in scored_routes[1:]:
                if route not in self.route_failures or self.route_failures[route] < 3:
                    best_route, best_score = route, score
                    break

        self.route_attempts[best_route] = self.route_attempts.get(best_route, 0) + 1

        # 6. Decide whether to delegate to Recon or Exploit
        evidence_for_route = [
            e for e in self.blackboard.evidence
            if e.route == best_route and e.score >= 0.3
        ]

        # For source_leak, always go directly to exploit (it's self-contained)
        if best_route == "source_leak":
            return AgentDecision(
                agent=self.agent_name,
                route=best_route,
                hypothesis=f"Exploit {best_route} (high-ROI, self-contained)",
                confidence=max(best_score, 0.5),
                supporting_evidence=[e.observation for e in evidence_for_route[:3]],
                next_action={"action": "delegate", "to": "exploit", "route": best_route},
                stop_if=["flag_found", "max_attempts_reached"],
                reasoning=f"Source leak is always worth trying — delegating to ExploitAgent",
            )

        if evidence_for_route:
            # Strong evidence — go to ExploitAgent
            best_ev = max(evidence_for_route, key=lambda e: e.score)
            return AgentDecision(
                agent=self.agent_name,
                route=best_route,
                hypothesis=f"Exploit {best_route} (evidence score: {best_ev.score:.2f})",
                confidence=best_ev.score,
                supporting_evidence=[best_ev.observation],
                next_action={"action": "delegate", "to": "exploit", "route": best_route},
                stop_if=["flag_found", "max_attempts_reached"],
                reasoning=f"Strong evidence for {best_route} — delegating to ExploitAgent",
            )
        else:
            # Check if we have param hints for this route — if so, go directly to exploit
            param_hints = [
                p for p in self.blackboard.state_summary().get("interesting_params", [])
                if best_route in (p.get("suspected_routes", []) or [])
            ]
            if param_hints:
                # Param hints exist — go directly to exploit
                # (no need to probe first; exploit steps are deterministic and cheap)
                return AgentDecision(
                    agent=self.agent_name,
                    route=best_route,
                    hypothesis=f"Exploit {best_route} (param hint: {param_hints[0].get('name')})",
                    confidence=0.5,
                    supporting_evidence=[f"Param '{param_hints[0].get('name')}' suspected for {best_route}"],
                    next_action={"action": "delegate", "to": "exploit", "route": best_route},
                    stop_if=["flag_found", "max_attempts_reached"],
                    reasoning=f"Param hint for {best_route} — delegating to ExploitAgent",
                )

            # Routes whose exploit steps are deterministic and cheap enough
            # to try without any evidence or param hints (probes may still
            # fail on some targets but exploit steps cover the gap).
            ALWAYS_EXPLOIT_ROUTES = {
                "lfi", "ssti", "sqli", "cmdi", "jwt", "graphql",
                "websocket", "xss", "upload",
                "ssrf", "idor", "php_pop",
            }
            if best_route in ALWAYS_EXPLOIT_ROUTES:
                return AgentDecision(
                    agent=self.agent_name,
                    route=best_route,
                    hypothesis=f"Exploit {best_route} (deterministic, no evidence needed)",
                    confidence=0.4,
                    next_action={"action": "delegate", "to": "exploit", "route": best_route},
                    stop_if=["flag_found", "max_attempts_reached"],
                    reasoning=f"{best_route} has deterministic exploit steps — delegating to ExploitAgent",
                )

            # No strong evidence — delegate to Recon for this route
            return AgentDecision(
                agent=self.agent_name,
                route=best_route,
                hypothesis=f"Probe {best_route} (priority: {self.ROUTE_PRIORITY.get(best_route, 5)})",
                confidence=best_score,
                next_action={"action": "delegate", "to": "recon", "route": best_route,
                            "task": f"probe_{best_route}"},
                stop_if=["no_evidence_after_probes", "route_invalid"],
                reasoning=f"Probing {best_route} — no strong evidence yet",
            )

    def _score_routes(self) -> List[Tuple[str, float]]:
        """Score all routes based on evidence, attempts, priority, and tech_stack.

        Scoring factors (Requirement 4.2):
          - Base priority score (from ROUTE_PRIORITY)
          - Evidence scores for the route (highest weight)
          - Parameter hints suggesting the route
          - Tech stack fingerprint boosts (PHP → source_leak/lfi/php_pop)
          - Penalty for route_failures history (repeated failures → lower score)
          - Penalty for too many attempts without progress
        """
        scores: List[Tuple[str, float]] = []

        state = self.blackboard.state_summary()
        evidence_list = state.get("top_evidence", [])
        params = state.get("interesting_params", [])
        tech_stack = state.get("tech_stack", [])

        for route_name in self.ROUTE_PRIORITY:
            if route_name == "recon":
                continue

            # Fix 3: Suppress source_leak when another route has strong evidence
            if route_name == "source_leak":
                has_strong_evidence = any(
                    ev.get("score", 0) >= 0.7
                    for ev in evidence_list
                    if ev.get("route") not in ("source_leak", "recon")
                )
                if has_strong_evidence:
                    continue

            score = 0.0

            # Base score from route priority
            score += self.ROUTE_PRIORITY.get(route_name, 5) * 0.05

            # Evidence score for this route — use max evidence score (strongest signal)
            route_evidence_scores = [
                ev.get("score", 0) for ev in evidence_list
                if ev.get("route") == route_name
            ]
            if route_evidence_scores:
                score += max(route_evidence_scores) * 0.5

            # Parameter hints
            for p in params:
                suspected = p.get("suspected_routes", [])
                if route_name in suspected:
                    score += 0.2

            # Tech stack fingerprint boosts (Requirement 4.2)
            php_routes = ["php_pop", "source_leak", "lfi", "ssti"]
            python_routes = ["ssti", "cmdi"]
            node_routes = ["ssrf", "ssti"]

            if any("php" in str(t).lower() for t in tech_stack):
                if route_name in php_routes:
                    score += 0.15  # PHP detected → boost PHP-related routes
            if any(t.lower() in ("flask", "django", "werkzeug") for t in tech_stack if isinstance(t, str)):
                if route_name in python_routes:
                    score += 0.12  # Python framework → boost ssti/cmdi
            if any(t.lower() in ("express", "node") for t in tech_stack if isinstance(t, str)):
                if route_name in node_routes:
                    score += 0.1  # Node.js → boost ssrf/ssti

            # Penalty for repeated failures (Requirement 4.2 — route_failures history)
            # Each consecutive failure shaves off enough from the score that a
            # route that has missed once is virtually guaranteed to be re-ranked
            # below any untried route in the same priority tier.  This is the
            # only reliable way to spread the limited round budget over the
            # 13 routes when running blind against the explore-21 set.
            failures = self.route_failures.get(route_name, 0)
            score -= failures * 0.35

            # Penalty for too many attempts
            attempts = self.route_attempts.get(route_name, 0)
            if attempts >= self.max_repeats_per_route:
                score -= 0.5

            if score > 0:
                scores.append((route_name, round(min(score, 1.0), 2)))

        # Sort by score descending (evidence-based ordering)
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    def process_exploit_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Process the result dict returned by ExploitAgent.execute().

        Handles each status:
          - "success" → verify flag and set stop condition
          - "handoff" → set next route to handoff_target
          - "failed"  → increment route_failures, penalize route score
          - "inconclusive" → increment route_attempts but don't penalize heavily
          - "error"   → treat as failure

        Returns a dict with:
          - stop: bool — whether the orchestrator should terminate
          - next_route: Optional[str] — route to switch to (for handoff)
          - flag: Optional[str] — verified flag value (for success)
        """
        route = result.get("route", "unknown")
        status = result.get("status", "failed")

        outcome: Dict[str, Any] = {
            "stop": False,
            "next_route": None,
            "flag": None,
        }

        if status == "success":
            # Flag found — verify and signal stop
            flag = result.get("flag")
            if flag:
                outcome["stop"] = True
                outcome["flag"] = flag
            # Reset failures for this route on success
            self.route_failures[route] = 0
            self.budget_remaining -= 1

        elif status == "handoff":
            # Switch to the handoff target route
            handoff_target = result.get("handoff_target")
            if handoff_target:
                outcome["next_route"] = handoff_target
                # Add evidence for the handoff target to boost its score
                self.blackboard.add_evidence(
                    route=handoff_target,
                    score=0.6,
                    source=f"handoff_from_{route}",
                    observation=f"Handoff from {route}: {result.get('stop_reason', '')}",
                )
            # Don't heavily penalize the source route — it found useful info
            self.route_attempts[route] = self.route_attempts.get(route, 0) + 1
            self.budget_remaining -= 1

        elif status == "failed":
            # Route failed — penalize score and track failure
            self.route_failures[route] = self.route_failures.get(route, 0) + 1
            # source_leak one-shot: never retry after first failure
            if route == "source_leak":
                self.route_failures[route] = 5
            self.budget_remaining -= 1

        elif status == "inconclusive":
            # Inconclusive — treat as soft failure so other routes get a chance.
            # Without penalty, false-positive evidence keeps inconclusive routes
            # at the top of the ranking indefinitely, starving other routes.
            self.route_attempts[route] = self.route_attempts.get(route, 0) + 1
            self.route_failures[route] = self.route_failures.get(route, 0) + 1
            self.budget_remaining -= 1

        else:
            # Unknown status or "error" — treat as failure
            self.route_failures[route] = self.route_failures.get(route, 0) + 1
            self.budget_remaining -= 1

        return outcome

    def record_result(self, route: str, success: bool) -> None:
        """Update route tracking after a specialist agent completes."""
        if success:
            self.route_failures[route] = 0
        else:
            self.route_failures[route] = self.route_failures.get(route, 0) + 1
        self.budget_remaining -= 1


# ---------------------------------------------------------------------------
# ReconAgent
# ---------------------------------------------------------------------------

class ReconAgent(BaseAgent):
    """Low-cost deterministic enumeration agent.

    Responsibilities:
      - Directory/file scanning
      - Form extraction and parsing
      - Parameter discovery
      - JS/resource analysis
      - HTTP header fingerprinting
      - Technology stack identification

    Minimizes LLM calls — most work is deterministic.
    """

    agent_name = "recon"

    # Common paths to scan
    COMMON_PATHS = [
        "/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
        "/admin/", "/login", "/register", "/api/", "/upload",
        "/index.php", "/config.php", "/wp-admin/", "/backup/",
    ]

    # Technology fingerprints
    TECH_SIGNATURES = {
        "PHP": [("Server", "PHP"), ("X-Powered-By", "PHP")],
        "Apache": [("Server", "Apache")],
        "nginx": [("Server", "nginx")],
        "Laravel": [("Set-Cookie", "laravel_session")],
        "ThinkPHP": [("Set-Cookie", "think_")],
        "Flask": [("Server", "Werkzeug")],
        "Django": [("Set-Cookie", "csrftoken"), ("Set-Cookie", "sessionid")],
        "Express": [("X-Powered-By", "Express")],
        "Spring": [("Set-Cookie", "JSESSIONID")],
    }

    def __init__(self, blackboard: WebStateBlackboard, target_url: str, session=None):
        super().__init__(blackboard, session)
        self.target_url = target_url.rstrip("/")

    def decide(self) -> AgentDecision:
        """Decide what recon action to take next."""
        state = self.blackboard.state_summary()

        # If no endpoints discovered, start with basic scan
        if state.get("endpoint_count", 0) == 0:
            return AgentDecision(
                agent=self.agent_name,
                route="recon",
                hypothesis="No endpoints discovered — start basic scan",
                confidence=0.9,
                next_action={"action": "scan_common_paths", "paths": self.COMMON_PATHS},
                reasoning="Initial reconnaissance — scanning common paths",
            )

        # If no tech stack identified, fingerprint
        if not state.get("tech_stack") or state.get("tech_stack") == ["unknown"]:
            return AgentDecision(
                agent=self.agent_name,
                route="recon",
                hypothesis="Technology stack unknown — fingerprint",
                confidence=0.8,
                next_action={"action": "fingerprint_tech", "url": self.target_url},
                reasoning="Need to identify technology stack for route selection",
            )

        # If no interesting params, extract from discovered endpoints
        if not state.get("interesting_params"):
            return AgentDecision(
                agent=self.agent_name,
                route="recon",
                hypothesis="No interesting parameters found",
                confidence=0.6,
                next_action={"action": "extract_params", "endpoints": state.get("key_endpoints", [])},
                reasoning="Parameter discovery needed for vulnerability detection",
            )

        # Recon complete
        return AgentDecision(
            agent=self.agent_name,
            route="recon",
            hypothesis="Reconnaissance sufficient",
            confidence=0.7,
            next_action={"action": "done"},
            reasoning="Basic recon complete — evidence available for route selection",
        )

    def execute(self, decision: AgentDecision) -> Dict[str, Any]:
        """Execute recon actions deterministically."""
        action = decision.next_action.get("action", "")
        results: Dict[str, Any] = {"action": action, "findings": []}

        if action == "scan_common_paths":
            results = self._scan_common_paths()
            # After scanning, also try to follow interesting links found
            if not self.blackboard.candidate_flags:
                link_results = self._follow_interesting_links()
                if link_results.get("findings"):
                    results.setdefault("link_findings", []).extend(link_results["findings"])
        elif action == "fingerprint_tech":
            results = self._fingerprint_tech()
        elif action == "extract_params":
            results = self._extract_params()
        elif action == "probe_source_leak":
            results = self._probe_route("source_leak")
        elif action and action.startswith("probe_"):
            route = action[6:]
            results = self._probe_route(route)

        # Update blackboard
        self._update_blackboard(results)
        return results

    def _scan_common_paths(self) -> Dict[str, Any]:
        """Scan common paths and record responses.

        Also extracts parameters from HTML links/forms and checks for flags
        directly in responses.
        """
        findings = []
        for path in self.COMMON_PATHS:
            try:
                url = self.target_url + path
                resp = self.session.get(url, timeout=10, allow_redirects=False)
                finding = {
                    "path": path,
                    "status": resp.status_code,
                    "length": len(resp.content) if resp.content else 0,
                    "content_type": resp.headers.get("Content-Type", ""),
                }
                findings.append(finding)

                # Auto-detect interesting patterns
                if resp.status_code == 200:
                    text = resp.text if resp.text else ""
                    text_lower = text.lower()

                    # Check for flag directly in response
                    flag = self.blackboard.check_and_record_flag(text, source=f"recon_scan:{path}")
                    if flag:
                        findings[-1]["flag_found"] = flag

                    if "flag" in text_lower:
                        findings[-1]["flag_hint"] = True
                    if "<form" in text_lower:
                        findings[-1]["has_forms"] = True

                    # Analyze JavaScript content
                    content_type = resp.headers.get("Content-Type", "")
                    if self._is_js_response(url, content_type) and text:
                        js_findings = self._analyze_js_content(url, text)
                        findings[-1]["js_analysis"] = js_findings

                    # Extract parameters from links (href="/?param=value")
                    self._extract_params_from_html(text, path)

                    # Also scan for <script src="..."> tags to discover JS files
                    self._discover_and_analyze_js_files(text)

                    # Extract evidence for source_leak routes
                    if path == "/.git/HEAD" and text.startswith("ref:"):
                        self.blackboard.add_evidence(
                            route="source_leak",
                            score=0.9,
                            source="recon_scan",
                            observation=f".git/HEAD accessible: {text.strip()[:80]}",
                        )
                    elif path == "/.env" and ("=" in text and len(text) > 20
                          and "<html" not in text_lower and "<body" not in text_lower):
                        self.blackboard.add_evidence(
                            route="source_leak",
                            score=0.85,
                            source="recon_scan",
                            observation=f".env file accessible ({len(text)} bytes)",
                        )

                    # --- Route fingerprinting from response content ---
                    if path == "/":
                        self._fingerprint_route_hints(text, text_lower, resp)

            except requests.RequestException:
                findings.append({"path": path, "status": "error"})

        return {"action": "scan_common_paths", "findings": findings}

    def _extract_params_from_html(self, html: str, page_path: str) -> None:
        """Extract URL parameters from HTML links and forms to populate blackboard params."""
        import re
        from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

        # Extract params from href links: href="/?page=xxx" or href="/path?file=xxx"
        link_pattern = re.compile(r'href=["\']([^"\']*\?[^"\']*)["\']', re.IGNORECASE)
        for match in link_pattern.finditer(html):
            link_url = match.group(1)
            try:
                parsed = _urlparse(link_url)
                params = _parse_qs(parsed.query)
                for param_name in params:
                    self.blackboard.record_param(
                        name=param_name,
                        location="query",
                        suspected_route="",  # Let get_interesting_params() classify
                    )
            except Exception:
                pass

        # Extract params from form inputs — detect form method to set correct location
        # First, build a map of form regions to their method
        form_pattern = re.compile(
            r'<form[^>]*>', re.IGNORECASE
        )
        form_method_pattern = re.compile(r'method=["\'](\w+)["\']', re.IGNORECASE)
        # Find all forms and their methods
        form_regions: list = []  # (start_pos, method)
        for fm in form_pattern.finditer(html):
            method_match = form_method_pattern.search(fm.group(0))
            method = method_match.group(1).upper() if method_match else "GET"
            form_regions.append((fm.start(), method))

        input_pattern = re.compile(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE
        )
        for match in input_pattern.finditer(html):
            param_name = match.group(1)
            # Determine location based on enclosing form's method
            location = "body"  # default for POST forms
            input_pos = match.start()
            for form_start, form_method in reversed(form_regions):
                if form_start < input_pos:
                    location = "query" if form_method == "GET" else "body"
                    break
            self.blackboard.record_param(
                name=param_name,
                location=location,
                suspected_route="",
            )

        # Extract params from action URLs in forms
        form_action_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*\?[^"\']*)["\']', re.IGNORECASE
        )
        for match in form_action_pattern.finditer(html):
            action_url = match.group(1)
            try:
                parsed = _urlparse(action_url)
                params = _parse_qs(parsed.query)
                for param_name in params:
                    self.blackboard.record_param(
                        name=param_name,
                        location="query",
                        suspected_route="",
                    )
            except Exception:
                pass

    def _fingerprint_route_hints(self, text: str, text_lower: str, resp) -> None:
        """Detect strong route signals from the homepage response.

        Adds high-score evidence (0.85) for routes that have clear fingerprints,
        so the Coordinator skips irrelevant routes and goes directly to the
        correct exploit on round 2.
        """
        import re

        headers = resp.headers

        # GraphQL: page mentions /graphql endpoint
        if "/graphql" in text_lower or "graphql" in text_lower:
            self.blackboard.add_evidence(
                route="graphql", score=0.85, source="recon_fingerprint",
                observation="GraphQL endpoint referenced on homepage",
            )

        # JWT: Set-Cookie contains eyJ (base64 JWT header)
        set_cookie = headers.get("Set-Cookie", "")
        if "eyJ" in set_cookie:
            self.blackboard.add_evidence(
                route="jwt", score=0.85, source="recon_fingerprint",
                observation="JWT token in Set-Cookie header",
            )

        # WebSocket: page mentions /ws/ or websocket connect endpoint
        if "/ws/" in text_lower or "ws/connect" in text_lower or "websocket" in text_lower:
            self.blackboard.add_evidence(
                route="websocket", score=0.85, source="recon_fingerprint",
                observation="WebSocket endpoint referenced on homepage",
            )

        # XSS: admin bot link present
        if "/admin/bot" in text_lower or "/admin/read" in text_lower:
            self.blackboard.add_evidence(
                route="xss", score=0.85, source="recon_fingerprint",
                observation="Admin bot/review endpoint found (XSS chain)",
            )

        # SQLi: SQL error keywords in response
        sql_signals = ["sql", "sqlite", "mysql", "syntax error", "query()", "prepare statement"]
        if any(sig in text_lower for sig in sql_signals):
            self.blackboard.add_evidence(
                route="sqli", score=0.85, source="recon_fingerprint",
                observation="SQL-related keywords in response",
            )

        # SQLi: search/product/profile pages strongly suggest DB-backed app
        db_page_signals = ["search results", "no products found", "user id", "profile"]
        if any(sig in text_lower for sig in db_page_signals):
            self.blackboard.add_evidence(
                route="sqli", score=0.80, source="recon_fingerprint",
                observation="Database-backed page detected (search/profile)",
            )

        # CMDi: ping/network tool pages suggest command injection
        cmdi_signals = ["ping tool", "network tool", "traceroute", "nslookup", "pinging"]
        if any(sig in text_lower for sig in cmdi_signals):
            self.blackboard.add_evidence(
                route="cmdi", score=0.85, source="recon_fingerprint",
                observation="Network/ping tool detected (command injection likely)",
            )

        # CMDi: input field named "ip" or page text containing "/?ip=" or "ping" in title
        has_ip_input = bool(re.search(r'<input[^>]*name=["\']ip["\']', text, re.IGNORECASE))
        has_ip_param_hint = "/?ip=" in text or "?ip=" in text_lower
        has_ping_title = bool(re.search(r'<title>[^<]*ping[^<]*</title>', text, re.IGNORECASE))
        if has_ip_input or has_ip_param_hint or has_ping_title:
            self.blackboard.add_evidence(
                route="cmdi", score=0.90, source="recon_fingerprint",
                observation="Ping/IP input detected (command injection likely)",
            )

        # --- Scenario hints for specific patterns ---

        # "fxck your space" → cmdi with space bypass
        if "fxck" in text_lower and "space" in text_lower:
            self.blackboard.add_scenario_hint(
                route="cmdi",
                scenario="cmdi",
                confidence=0.9,
                source="recon_fingerprint",
                detail="Page contains 'fxck your space' — space bypass needed",
                payload_family="space_bypass",
            )

        # SQL error keywords → sqli error_based
        sql_error_signals = ["sql syntax", "mysql_fetch", "sqlite3", "pg_query", "odbc"]
        if any(sig in text_lower for sig in sql_error_signals):
            self.blackboard.add_scenario_hint(
                route="sqli",
                scenario="sqli",
                confidence=0.85,
                source="recon_fingerprint",
                detail="SQL error keywords detected — error-based injection",
                payload_family="error_based",
            )

        # "md5" in page → php_pop with md5 type juggling
        if "md5" in text_lower:
            self.blackboard.add_scenario_hint(
                route="php_pop",
                scenario="php_pop",
                confidence=0.7,
                source="recon_fingerprint",
                detail="md5 reference in page — possible type juggling",
                payload_family="md5_type_juggling",
            )

    def _follow_interesting_links(self) -> Dict[str, Any]:
        """Follow links discovered during scan that might contain flags directly.

        This handles cases where the target's homepage has links like
        /?page=/tmp/flag or /?file=/flag that would directly reveal the flag.
        """
        import re
        from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs, urljoin

        findings = []

        # Strategy 1: Follow all discovered links with parameters
        # These were extracted during _scan_common_paths → _extract_params_from_html
        # Re-scan the root page to find actual link URLs
        try:
            resp = self.session.get(self.target_url + "/", timeout=10)
            if resp.status_code == 200:
                # Extract all href links with query params
                link_pattern = re.compile(r'href=["\']([^"\']*\?[^"\']*)["\']', re.IGNORECASE)
                for match in link_pattern.finditer(resp.text):
                    link_url = match.group(1)
                    full_url = urljoin(self.target_url + "/", link_url)
                    try:
                        link_resp = self.session.get(full_url, timeout=10)
                        if link_resp.status_code == 200:
                            flag = self.blackboard.check_and_record_flag(
                                link_resp.text, source=f"recon_follow_link:{link_url}"
                            )
                            if flag:
                                findings.append({"path": link_url, "flag_found": flag})
                                return {"action": "follow_links", "findings": findings}
                    except Exception:
                        pass
        except Exception:
            pass

        # Strategy 2: For each interesting param, try common flag paths
        interesting = self.blackboard.get_interesting_params()
        if not interesting:
            return {"action": "follow_links", "findings": findings}

        for param in interesting[:3]:
            if "lfi" in param.suspected_routes or any(
                kw in param.name.lower() for kw in ("file", "page", "path", "include")
            ):
                flag_paths = [
                    "/flag", "/flag.txt", "/tmp/flag", "/tmp/flag.txt",
                    "/app/flag.txt", "/app/flag", "/var/www/flag.txt",
                    "/proc/self/environ",
                ]
                for flag_path in flag_paths:
                    try:
                        url = f"{self.target_url}/?{param.name}={flag_path}"
                        resp = self.session.get(url, timeout=10, allow_redirects=False)
                        if resp.status_code == 200:
                            flag = self.blackboard.check_and_record_flag(
                                resp.text, source=f"recon_link:{param.name}={flag_path}"
                            )
                            if flag:
                                findings.append({
                                    "path": f"/?{param.name}={flag_path}",
                                    "flag_found": flag,
                                })
                                return {"action": "follow_links", "findings": findings}
                    except Exception:
                        pass

        return {"action": "follow_links", "findings": findings}

    def _fingerprint_tech(self) -> Dict[str, Any]:
        """Fingerprint technology stack from response headers."""
        try:
            resp = self.session.get(self.target_url, timeout=10, allow_redirects=False)
        except requests.RequestException:
            return {"action": "fingerprint_tech", "error": "Connection failed"}

        tech = []
        headers = dict(resp.headers)

        for tech_name, signatures in self.TECH_SIGNATURES.items():
            for header_name, value in signatures:
                header_val = headers.get(header_name, "")
                if value.lower() in header_val.lower():
                    if tech_name not in tech:
                        tech.append(tech_name)

        # Check response body for framework clues
        text = resp.text.lower() if resp.text else ""
        if "wp-content" in text:
            tech.append("WordPress")
        if "drupal" in text:
            tech.append("Drupal")
        if "joomla" in text:
            tech.append("Joomla")

        return {
            "action": "fingerprint_tech",
            "tech_stack": tech or ["unknown"],
            "server": headers.get("Server", ""),
            "powered_by": headers.get("X-Powered-By", ""),
        }

    def _extract_params(self) -> Dict[str, Any]:
        """Extract parameters from discovered endpoints."""
        findings = []
        state = self.blackboard.state_summary()
        endpoints = state.get("key_endpoints", [])

        for ep in endpoints:
            for form in self.blackboard.forms:
                findings.append({
                    "endpoint": ep,
                    "form_action": form.action,
                    "fields": [f.name for f in form.fields],
                })

        return {"action": "extract_params", "findings": findings}

    def _probe_route(self, route: str) -> Dict[str, Any]:
        """Run probes for a specific route using the route state machine."""
        try:
            machine = create_machine(route, self.target_url, session=self.session)
            if machine is None:
                return {"action": f"probe_{route}", "error": f"No machine for {route}"}

            state = self.blackboard.state_summary()
            met, reason = machine.preconditions_met(state)
            if not met:
                return {"action": f"probe_{route}", "preconditions_met": False, "reason": reason}

            evidence = machine.run_probes()
            status = machine.get_status()

            return {
                "action": f"probe_{route}",
                "preconditions_met": True,
                "evidence_score": evidence.score,
                "evidence_detail": evidence.detail,
                "probe_results": {k: v.value for k, v in machine.state.probe_results.items()},
                "status": status,
            }
        except Exception as e:
            return {"action": f"probe_{route}", "error": str(e)}

    def _update_blackboard(self, results: Dict[str, Any]) -> None:
        """Update blackboard with recon findings."""
        # Ingest using the standard blackboard interface
        self.blackboard.ingest_tool_result(
            f"recon_{results.get('action', 'unknown')}",
            {},
            results,
        )

        # Update endpoints
        for finding in results.get("findings", []):
            path = finding.get("path", "")
            if path and finding.get("status") in (200, 301, 302, 403, 405):
                self.blackboard.record_endpoint(
                    path=path,
                    method="GET",
                    status_code=finding.get("status", 0),
                    discovered_from="recon_scan",
                )

        # Update tech stack
        tech_stack = results.get("tech_stack", [])
        if tech_stack:
            for tech_str in tech_stack:
                if isinstance(tech_str, str) and tech_str not in self.blackboard.tech_stack:
                    self.blackboard.tech_stack.append(tech_str)

    # ------------------------------------------------------------------
    # JS Analysis integration
    # ------------------------------------------------------------------

    def _discover_and_analyze_js_files(self, html: str) -> None:
        """Discover JS files referenced in HTML and analyze them.

        Scans for <script src="..."> tags, fetches the JS content,
        and runs JSAnalyzer on each discovered file.
        """
        import re
        from urllib.parse import urljoin

        script_pattern = re.compile(
            r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
        )
        analyzed_urls: set = set()

        for match in script_pattern.finditer(html):
            src = match.group(1)
            # Skip external CDN scripts (only analyze same-origin JS)
            if src.startswith("http") and self.target_url not in src:
                continue
            # Build full URL
            full_url = urljoin(self.target_url + "/", src)
            if full_url in analyzed_urls:
                continue
            analyzed_urls.add(full_url)

            try:
                resp = self.session.get(full_url, timeout=10)
                if resp.status_code == 200 and resp.text:
                    content_type = resp.headers.get("Content-Type", "")
                    if self._is_js_response(full_url, content_type) or src.endswith(".js"):
                        self._analyze_js_content(full_url, resp.text)
            except requests.RequestException:
                pass

    def _is_js_response(self, url: str, content_type: str) -> bool:
        """Determine if a response contains JavaScript content."""
        ct_lower = content_type.lower()
        if "javascript" in ct_lower or "application/x-javascript" in ct_lower:
            return True
        # Check URL extension as fallback
        url_lower = url.lower().split("?")[0]
        return url_lower.endswith(".js")

    def _analyze_js_content(self, url: str, content: str) -> Dict[str, Any]:
        """Analyze JavaScript content using JSAnalyzer.

        Extracts API endpoints, secrets, source maps, and routes from JS content.
        Records findings to the blackboard:
          - API endpoints → blackboard.endpoints
          - Source maps → blackboard evidence for later download
          - Secrets → blackboard evidence with high score

        Returns a summary dict of findings.
        """
        analyzer = JSAnalyzer()
        findings: Dict[str, Any] = {"url": url, "js_analysis": True}

        # 1. Extract API endpoints and record to blackboard
        api_endpoints = analyzer.extract_api_endpoints(content)
        findings["api_endpoints"] = api_endpoints
        for endpoint in api_endpoints:
            self.blackboard.record_endpoint(
                path=endpoint,
                method="GET",
                discovered_from=f"js_analysis:{url}",
            )

        # 2. Detect source map and record to blackboard for later download
        source_map_url = analyzer.detect_source_map(content)
        findings["source_map"] = source_map_url
        if source_map_url:
            # Record source map as evidence for source_leak route
            self.blackboard.add_evidence(
                route="source_leak",
                score=0.7,
                source="js_analyzer",
                observation=f"Source map found in {url}: {source_map_url}",
            )
            # Also record the source map URL as an endpoint for later download
            self.blackboard.record_endpoint(
                path=source_map_url,
                method="GET",
                discovered_from=f"js_source_map:{url}",
            )

        # 3. Extract secrets and record as high-value evidence
        secrets = analyzer.extract_secrets(content)
        findings["secrets"] = secrets
        for secret in secrets:
            self.blackboard.add_evidence(
                route="source_leak",
                score=0.85,
                source="js_analyzer",
                observation=f"Secret ({secret['type']}) found in {url}: {secret['value'][:30]}...",
            )

        # 4. Extract frontend routes (informational, helps discover endpoints)
        routes = analyzer.extract_routes(content)
        findings["frontend_routes"] = routes
        for route_path in routes:
            if route_path.startswith("/"):
                self.blackboard.record_endpoint(
                    path=route_path,
                    method="GET",
                    discovered_from=f"js_routes:{url}",
                )

        if api_endpoints or source_map_url or secrets:
            log.info(
                "JS analysis of %s: %d endpoints, source_map=%s, %d secrets",
                url, len(api_endpoints), bool(source_map_url), len(secrets),
            )

        return findings


# ---------------------------------------------------------------------------
# ExploitAgent
# ---------------------------------------------------------------------------

class ExploitAgent(BaseAgent):
    """Constructs payloads and executes RouteStateMachines.

    Responsibilities:
      - Run route state machines for a given route
      - Interpret probe and exploit results
      - Update evidence on blackboard
      - Report success/failure to Coordinator
    """

    agent_name = "exploit"

    def __init__(self, blackboard: WebStateBlackboard, target_url: str, session=None):
        super().__init__(blackboard, session)
        self.target_url = target_url.rstrip("/")

    def decide(self, suggested_route: str = "") -> AgentDecision:
        """Decide exploitation approach based on blackboard evidence.

        Args:
            suggested_route: Route suggested by Coordinator (always used
                             when provided, regardless of existing evidence).
        """
        state = self.blackboard.state_summary()
        top_evidence = state.get("top_evidence", [])

        # Coordinator directive takes priority — the Coordinator has a global
        # view of route scores, failures, and param hints that the ExploitAgent
        # does not independently evaluate.
        if suggested_route:
            return AgentDecision(
                agent=self.agent_name,
                route=suggested_route,
                hypothesis=f"Exploit {suggested_route} (coordinator directive)",
                confidence=0.55,
                next_action={
                    "action": "run_state_machine",
                    "route": suggested_route,
                },
                stop_if=["flag_found", "max_attempts_reached"],
                reasoning=f"Coordinator selected {suggested_route} — running state machine",
            )

        if not top_evidence:
            return AgentDecision(
                agent=self.agent_name,
                route="unknown",
                hypothesis="No evidence to exploit",
                confidence=0.0,
                next_action={"action": "none"},
                reasoning="No evidence available — need recon first",
            )

        best = top_evidence[0]
        route = best.get("route", "source_leak")
        score = best.get("score", 0)
        card = get_route_card(route)

        return AgentDecision(
            agent=self.agent_name,
            route=route,
            hypothesis=f"Exploit {route} with evidence score {score:.2f}",
            confidence=min(score, 0.9),
            supporting_evidence=[best.get("detail", "")],
            next_action={
                "action": "run_state_machine",
                "route": route,
                "probes": card.probes[:5],
                "exploit_steps": card.exploit_steps[:3],
            },
            stop_if=["flag_found", "max_attempts_reached"] + card.stop_conditions[:2],
            reasoning=f"Running {route} state machine — evidence score {score:.2f}",
        )

    def execute(self, decision: AgentDecision) -> Dict[str, Any]:
        """Execute exploit via route state machine.

        Uses run_route() as the primary execution path, returning structured
        results based on RouteResult status.
        """
        route = decision.next_action.get("route", decision.route)
        if not route or route == "unknown":
            return {"error": "No route specified"}

        try:
            # Detect param name from blackboard state
            state = self.blackboard.state_summary()
            param_name = None
            for p in state.get("interesting_params", []):
                suspected = p.get("suspected", []) or p.get("suspected_routes", [])
                if route in suspected:
                    param_name = p.get("name")
                    break

            # Call run_route() with RouteResult return type
            result: RouteResult = run_route(
                route=route,
                target_url=self.target_url,
                blackboard_state=state,
                param_name=param_name,
                session=self.session,
                max_steps=10,
                blackboard=self.blackboard,
            )

            # Handle RouteResult statuses
            if result.status == "success":
                # Flag found — record to blackboard
                if result.flag:
                    self.blackboard.add_flag_candidate(
                        result.flag, source=f"exploit_{route}", confidence=0.9
                    )
                # Record evidence
                if result.best_evidence_score > 0:
                    self.blackboard.add_evidence(
                        route=route,
                        score=result.best_evidence_score,
                        source=f"exploit_{route}",
                        observation=f"ExploitAgent: flag_found via {route}",
                    )
                return {
                    "action": "run_state_machine",
                    "route": route,
                    "found_flag": True,
                    "flag": result.flag,
                    "status": result.status,
                    "steps_executed": result.steps_executed,
                    "stop_reason": result.stop_reason,
                }

            elif result.status == "handoff":
                # Route suggests switching to another route
                if result.best_evidence_score > 0:
                    self.blackboard.add_evidence(
                        route=route,
                        score=result.best_evidence_score,
                        source=f"exploit_{route}",
                        observation=f"ExploitAgent: handoff to {result.handoff_target}",
                    )
                return {
                    "action": "run_state_machine",
                    "route": route,
                    "found_flag": False,
                    "flag": None,
                    "status": result.status,
                    "handoff_target": result.handoff_target,
                    "steps_executed": result.steps_executed,
                    "stop_reason": result.stop_reason,
                }

            elif result.status == "inconclusive":
                # Not enough evidence or max steps reached
                if result.best_evidence_score > 0:
                    self.blackboard.add_evidence(
                        route=route,
                        score=result.best_evidence_score,
                        source=f"exploit_{route}",
                        observation=f"ExploitAgent: inconclusive ({result.stop_reason})",
                    )
                return {
                    "action": "run_state_machine",
                    "route": route,
                    "found_flag": False,
                    "flag": None,
                    "status": result.status,
                    "steps_executed": result.steps_executed,
                    "stop_reason": result.stop_reason,
                }

            else:  # status == "failed"
                # Route failed — record evidence if any
                if result.best_evidence_score > 0:
                    self.blackboard.add_evidence(
                        route=route,
                        score=result.best_evidence_score,
                        source=f"exploit_{route}",
                        observation=f"ExploitAgent: failed ({result.stop_reason})",
                    )
                return {
                    "action": "run_state_machine",
                    "route": route,
                    "found_flag": False,
                    "flag": None,
                    "status": result.status,
                    "steps_executed": result.steps_executed,
                    "stop_reason": result.stop_reason,
                }

        except Exception as e:
            # Catch any exception and return error result
            log.error(f"ExploitAgent error on route {route}: {e}", exc_info=True)
            self.blackboard.record_attempt(
                route=route,
                tool=f"route_sm_{route}",
                args={"route": route, "target_url": self.target_url},
                success=False,
                result_summary=f"Exception: {str(e)[:200]}",
                failure_reason=str(e)[:200],
            )
            return {
                "action": "run_state_machine",
                "route": route,
                "found_flag": False,
                "flag": None,
                "status": "error",
                "error": str(e),
            }

    # ------------------------------------------------------------------
    # LLM-in-the-loop fallback
    # ------------------------------------------------------------------

    def _llm_fallback(self, route: str, result: RouteResult) -> Optional[str]:
        """Multi-turn LLM-driven exploit when the state machine fails.

        Strategy:
          1. Feed LLM the target URL, route type, and recent HTTP responses
          2. LLM suggests an HTTP request (method, path, params, headers, data)
          3. Execute it, check for flag
          4. If no flag, feed the response back to LLM for up to MAX_LLM_TURNS
          5. Return flag if found, None otherwise

        This is the key differentiator from a pure fuzzer: the LLM can
        analyze responses, understand error messages, and construct
        targeted payloads that aren't in any pre-built list.
        """
        MAX_LLM_TURNS = 3

        try:
            from autopnex.orchestrator.llm_client import LLMClient
        except Exception:
            return None

        try:
            llm = LLMClient()
            if not llm.enabled:
                return None

            # Collect context: recent HTTP responses from state machine attempts
            attempts = [a for a in self.blackboard.attempts if a.route == route]
            recent = attempts[-3:] if attempts else []
            history_lines = []
            for att in recent:
                summary = att.result_summary or f"{att.tool} -> {'ok' if att.success else 'fail'}"
                history_lines.append(f"  - {summary[:300]}")
            formatted_history = "\n".join(history_lines) if history_lines else "  (no prior attempts)"

            # Also grab the last few HTTP responses from the state machine
            # (stored in blackboard endpoints as status codes, but we need actual content)
            # Fetch the target homepage for initial context
            try:
                homepage_resp = self.session.get(self.target_url, timeout=10, allow_redirects=True)
                homepage_preview = homepage_resp.text[:1500] if homepage_resp.text else "(empty)"
            except Exception:
                homepage_preview = "(failed to fetch)"

            # Build initial system + user messages for multi-turn conversation
            system_msg = {
                "role": "system",
                "content": (
                    "You are an expert Web CTF player. Your goal is to find the flag on the target.\n"
                    "The deterministic exploit engine already tried common payloads and failed.\n"
                    "Now YOU must analyze the target's responses and craft precise payloads.\n\n"
                    "Rules:\n"
                    "- Reply with EXACTLY one JSON object per turn (no markdown, no explanation)\n"
                    "- Format: {\"method\": \"GET|POST\", \"path\": \"/...\", \"params\": {}, "
                    "\"headers\": {}, \"data\": \"...\", \"reasoning\": \"...\"}\n"
                    "- If you believe the target is unsolvable, reply: {\"give_up\": true}\n"
                    "- Analyze each response carefully — look for error messages, hints, "
                    "parameter names, SQL errors, template syntax, file paths, etc.\n"
                    "- The flag format is typically: flag{...}\n"
                    "- Common CTF techniques: SQLi, SSTI, LFI, CMDi, JWT manipulation, "
                    "SSRF, file upload, deserialization, IDOR, XSS+admin bot"
                ),
            }

            user_msg_initial = {
                "role": "user",
                "content": (
                    f"Target: {self.target_url}\n"
                    f"Route attempted: {route}\n"
                    f"State machine result: status={result.status}, "
                    f"stop_reason={result.stop_reason}, "
                    f"steps_executed={result.steps_executed}\n\n"
                    f"Prior attempts:\n{formatted_history}\n\n"
                    f"Homepage response (first 1500 chars):\n{homepage_preview}\n\n"
                    f"Analyze the homepage and suggest your first exploit request."
                ),
            }

            messages = [system_msg, user_msg_initial]

            for turn in range(MAX_LLM_TURNS):
                resp = llm.chat(messages, temperature=0.3, max_tokens=800)
                content = resp.get("content", "")
                if not content:
                    return None

                # Parse LLM response
                # Strip markdown code fences if present
                clean = content.strip()
                if clean.startswith("```"):
                    clean = clean.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

                try:
                    payload = json.loads(clean)
                except json.JSONDecodeError:
                    # Try to extract JSON from mixed text
                    import re as _re
                    json_match = _re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean)
                    if json_match:
                        try:
                            payload = json.loads(json_match.group(0))
                        except json.JSONDecodeError:
                            return None
                    else:
                        return None

                if payload.get("give_up") or payload.get("skip"):
                    return None

                # Execute the suggested request
                method = payload.get("method", "GET").upper()
                path = payload.get("path", "/")
                params = payload.get("params") or {}
                headers = payload.get("headers") or {}
                data = payload.get("data")

                url = self.target_url.rstrip("/") + "/" + path.lstrip("/")
                try:
                    if method == "POST":
                        http_resp = self.session.post(
                            url, params=params, data=data, headers=headers,
                            timeout=15, allow_redirects=True,
                        )
                    else:
                        http_resp = self.session.get(
                            url, params=params, headers=headers,
                            timeout=15, allow_redirects=True,
                        )
                except Exception as e:
                    # Network error — tell LLM and let it try again
                    messages.append({"role": "assistant", "content": content})
                    messages.append({
                        "role": "user",
                        "content": f"Request failed with error: {e}\nTry a different approach.",
                    })
                    continue

                response_text = http_resp.text[:2000] if http_resp.text else "(empty)"

                # Check for flag in response
                flag = self.blackboard.check_and_record_flag(
                    http_resp.text, source=f"llm_fallback_{route}_turn{turn}"
                )
                if flag:
                    log.info(
                        "LLM-in-the-loop found flag on turn %d for route %s: %s",
                        turn + 1, route, flag[:40],
                    )
                    return flag

                # No flag yet — feed response back to LLM for next turn
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": (
                        f"HTTP {http_resp.status_code} response "
                        f"({len(http_resp.text or '')} bytes):\n"
                        f"{response_text}\n\n"
                        f"No flag found yet. Analyze this response and suggest "
                        f"your next request. Look for clues in error messages, "
                        f"HTML structure, headers, or parameter names."
                    ),
                })

            # All turns exhausted
            return None

        except Exception as e:
            log.debug(f"LLM fallback error for route {route}: {e}")
            return None


# ---------------------------------------------------------------------------
# CriticAgent
# ---------------------------------------------------------------------------

class CriticAgent(BaseAgent):
    """Reviews agent decisions for errors, repeats, and weak hypotheses.

    Responsibilities:
      - Check for repeated failed actions
      - Refute hypotheses lacking evidence
      - Suggest route switches when evidence is weak
      - Prevent infinite loops

    Must reference specific evidence and attempts — never opinion-only.
    """

    agent_name = "critic"

    # Thresholds
    MAX_REPEAT_ATTEMPTS = 3       # Same tool+args combination
    MAX_ROUTE_ATTEMPTS = 5        # Same route without progress
    LOW_EVIDENCE_THRESHOLD = 0.35  # Below this, suggest switch

    def __init__(self, blackboard: WebStateBlackboard, session=None):
        super().__init__(blackboard, session)
        self._seen_attempts: Dict[str, int] = {}  # hash -> count
        self._route_progress: Dict[str, int] = {}  # route -> evidence count

    def decide(self) -> AgentDecision:
        """Review current blackboard state and produce critique.

        Enhanced repeat detection (Requirement 4.5):
          When same (tool, args_hash) appears ≥ 3 times, force route switch
          by setting next_action to "force_switch" and writing the recommendation
          into supporting_evidence.
        """
        critiques: List[str] = []
        suggestions: List[str] = []

        # 1. Check for repeated attempts — force switch if threshold met
        repeats = self._check_repeats()
        force_switch = False
        if repeats:
            critiques.append(f"Repeated attempts detected: {repeats}")
            # Force route switch when repeats are detected (Requirement 4.5)
            force_switch = True
            suggestions.append("FORCE_SWITCH: Same (tool, args) repeated ≥ 3 times — must switch route")

        # 2. Check evidence quality
        evidence_list = self.blackboard.evidence
        if evidence_list:
            best = max(evidence_list, key=lambda e: e.score)
            if best.score < self.LOW_EVIDENCE_THRESHOLD:
                critiques.append(f"Best evidence score ({best.score:.2f}) below threshold")
                suggestions.append("Switch to higher-priority route or restart recon")
        else:
            critiques.append("No evidence collected yet")

        # 3. Check route focus
        routes = set(e.route for e in evidence_list)
        state = self.blackboard.state_summary()
        failed_routes = state.get("failed_attempts", 0)
        if failed_routes > 2 and len(routes) == 1:
            critiques.append(f"Only {routes} tried with {failed_routes} failures")
            suggestions.append("Try alternate route — current route may be invalid")

        # 4. Check for blocker resolution
        if self.blackboard.blockers:
            critiques.append(f"Unresolved blockers: {self.blackboard.blockers}")

        # 5. Flag verification
        flags = self.blackboard.candidate_flags
        unverified = [f for f in flags if not f.verified]
        if unverified:
            suggestions.append(f"Verify {len(unverified)} unverified flag candidates")

        confidence = 1.0 - (len(critiques) * 0.15)  # Lower confidence with more critiques
        confidence = max(0.1, min(1.0, confidence))

        next_action: Dict[str, Any] = {"action": "none"}
        if force_switch:
            # Requirement 4.5: Force route switch when repeats detected
            next_action = {
                "action": "force_switch",
                "reason": "repeat_threshold_exceeded",
                "suggestions": suggestions,
            }
        elif suggestions:
            next_action = {
                "action": "suggest_switch" if "Switch" in str(suggestions) else "flag_corrections",
                "suggestions": suggestions,
            }

        return AgentDecision(
            agent=self.agent_name,
            route="critic",
            hypothesis=f"Critique: {len(critiques)} issues, {len(suggestions)} suggestions",
            confidence=round(confidence, 2),
            supporting_evidence=critiques + (
                [f"FORCE_SWITCH: {r}" for r in repeats] if force_switch else []
            ),
            next_action=next_action,
            stop_if=["no_issues", "coordinator_override"],
            reasoning="; ".join(critiques) if critiques else "No issues detected",
        )

    def _check_repeats(self) -> List[str]:
        """Check for repeated tool calls (Requirement 4.5).

        When same tool is used ≥ MAX_REPEAT_ATTEMPTS (3) times without success,
        returns the repeat info so decide() can force a route switch.

        Note: The blackboard deduplicates exact (tool, args_hash) pairs, so we
        count by tool name across all attempts for the same route.
        """
        # Count failed attempts per (route, tool) combination
        route_tool_counts: Dict[str, int] = {}
        for attempt in self.blackboard.attempts:
            if not attempt.success:
                key = f"{attempt.route}:{attempt.tool}"
                route_tool_counts[key] = route_tool_counts.get(key, 0) + 1

        repeats = []
        for key, count in route_tool_counts.items():
            if count >= self.MAX_REPEAT_ATTEMPTS:
                route_name, tool_name = key.split(":", 1)
                repeats.append(
                    f"{tool_name} failed {count} times on route {route_name}"
                )

        return repeats

    def record_attempt(self, tool_name: str, args_hash: str) -> None:
        """Record an attempt for repeat detection."""
        key = f"{tool_name}:{args_hash}"
        self._seen_attempts[key] = self._seen_attempts.get(key, 0) + 1


# ---------------------------------------------------------------------------
# Multi-agent orchestrator
# ---------------------------------------------------------------------------

class MultiAgentOrchestrator:
    """Orchestrates the multi-agent collaboration loop.

    Flow:
      1. Coordinator decides route/action
      2. If recon needed → ReconAgent.execute()
      3. If exploit needed → ExploitAgent.execute()
      4. After each action → CriticAgent.decide()
      5. Coordinator.record_result()
      6. Repeat until flag found or budget exhausted

    All agents share the same WebStateBlackboard.
    """

    def __init__(
        self,
        target_url: str,
        flag_format: str = r"flag\{[^}]+\}",
        max_rounds: int = 15,
        session: Optional[requests.Session] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.flag_format = flag_format

        # Shared blackboard
        self.blackboard = WebStateBlackboard(target_url=target_url, flag_format=flag_format)

        # Specialist agents
        session = session or requests.Session()
        self.coordinator = CoordinatorAgent(self.blackboard, session=session, max_rounds=max_rounds)
        self.recon = ReconAgent(self.blackboard, target_url, session=session)
        self.exploit = ExploitAgent(self.blackboard, target_url, session=session)
        self.critic = CriticAgent(self.blackboard, session=session)

    def run_loop(self, max_rounds: int = 15) -> Tuple[bool, Optional[str], List[Dict[str, Any]]]:
        """Run the multi-agent collaboration loop.

        Returns (found_flag, flag_value, action_log).

        When max_rounds is exhausted without a verified flag (Requirement 4.6):
          - Returns highest-confidence candidate flag if any exist
          - Otherwise returns (False, None, action_log)
        """
        action_log: List[Dict[str, Any]] = []

        for round_num in range(1, max_rounds + 1):
            log.info("Multi-agent round %d/%d", round_num, max_rounds)

            # Phase 1: Coordinator decides
            coord_decision = self.coordinator.decide()
            action_log.append({
                "round": round_num,
                "phase": "coordinate",
                "agent": "coordinator",
                "decision": coord_decision.to_dict(),
            })

            # Check stop condition
            if coord_decision.next_action.get("action") == "stop":
                flags = self.blackboard.candidate_flags
                best_flag = flags[0].value if flags else None
                return True, best_flag, action_log

            # Phase 2: Execute based on delegation
            target = coord_decision.next_action.get("to", "recon")
            exec_result: Dict[str, Any] = {}

            if target == "recon":
                recon_decision = self.recon.decide()
                action_log.append({
                    "round": round_num,
                    "phase": "recon_decide",
                    "agent": "recon",
                    "decision": recon_decision.to_dict(),
                })
                exec_result = self.recon.execute(recon_decision)

            elif target == "exploit":
                exploit_decision = self.exploit.decide(
                    suggested_route=coord_decision.route
                )
                action_log.append({
                    "round": round_num,
                    "phase": "exploit_decide",
                    "agent": "exploit",
                    "decision": exploit_decision.to_dict(),
                })
                exec_result = self.exploit.execute(exploit_decision)

            action_log.append({
                "round": round_num,
                "phase": "execute",
                "agent": target,
                "result_summary": str(exec_result)[:500],
            })

            # Phase 3: Process exploit result via Coordinator
            if target == "exploit" and exec_result.get("status"):
                outcome = self.coordinator.process_exploit_result(exec_result)
                action_log.append({
                    "round": round_num,
                    "phase": "process_result",
                    "agent": "coordinator",
                    "outcome": outcome,
                })

                # Stop if flag verified
                if outcome["stop"]:
                    return True, outcome["flag"], action_log

                # Handle handoff — set next route hint for coordinator
                if outcome["next_route"]:
                    # Add evidence to boost the handoff target so coordinator
                    # picks it up in the next round's _score_routes()
                    log.info("Handoff to route: %s", outcome["next_route"])

            else:
                # Non-exploit actions (recon) — use legacy record_result
                route = coord_decision.route
                success = exec_result.get("found_flag", False)
                self.coordinator.record_result(route, success)

            # Check for flag in execution result (fallback)
            if exec_result.get("found_flag"):
                flag = exec_result.get("flag")
                return True, flag, action_log

            # Check for flag candidates found during recon or exploit
            for flag_candidate in self.blackboard.candidate_flags:
                if flag_candidate.confidence >= 0.8:
                    return True, flag_candidate.value, action_log

            # Phase 4: Critic reviews
            critic_decision = self.critic.decide()
            action_log.append({
                "round": round_num,
                "phase": "critic",
                "agent": "critic",
                "decision": critic_decision.to_dict(),
            })

            # Handle CriticAgent force_switch recommendation (Requirement 4.5)
            if critic_decision.next_action.get("action") == "force_switch":
                # Skip the current route by incrementing its failure count
                current_route = coord_decision.route
                if current_route and current_route != "recon":
                    self.coordinator.route_failures[current_route] = \
                        self.coordinator.route_failures.get(current_route, 0) + 1
                    log.info(
                        "CriticAgent forced route switch from %s (repeat threshold exceeded)",
                        current_route,
                    )

            # Check for flag candidates after critic review
            for flag_candidate in self.blackboard.candidate_flags:
                if flag_candidate.confidence >= 0.8:
                    return True, flag_candidate.value, action_log

        # Requirement 4.6: max_rounds exhausted — graceful degradation

        # LLM-in-the-loop fallback: when all deterministic routes failed,
        # give the LLM 3 turns to analyze the target and find the flag.
        # This is the key capability upgrade — the LLM can handle novel
        # challenges that aren't covered by the state machine's payload lists.
        if not self.blackboard.candidate_flags:
            # Find the route with the best evidence to give LLM context
            best_route = "sqli"  # default
            best_ev_score = 0.0
            for ev in self.blackboard.evidence:
                if ev.score > best_ev_score and ev.route != "source_leak":
                    best_ev_score = ev.score
                    best_route = ev.route

            from .route_state_machine import RouteResult as _RR
            dummy_result = _RR(
                route=best_route,
                status="failed",
                best_evidence_score=best_ev_score,
                steps_executed=0,
                stop_reason="all_routes_exhausted",
            )
            llm_flag = self.exploit._llm_fallback(best_route, dummy_result)
            if llm_flag:
                action_log.append({
                    "round": max_rounds + 1,
                    "phase": "llm_fallback",
                    "agent": "exploit",
                    "result_summary": f"LLM fallback found flag: {llm_flag[:40]}",
                })
                return True, llm_flag, action_log

        # Return highest-confidence candidate flag if any exist
        if self.blackboard.candidate_flags:
            best_candidate = max(
                self.blackboard.candidate_flags, key=lambda f: f.confidence
            )
            if best_candidate.confidence > 0:
                log.info(
                    "Max rounds exhausted. Returning best candidate flag "
                    "(confidence=%.2f): %s",
                    best_candidate.confidence,
                    best_candidate.value,
                )
                return False, best_candidate.value, action_log

        return False, None, action_log

    def solve(
        self,
        target_url: Optional[str] = None,
        flag_format: str = r"[A-Za-z0-9_]+\{[^}]+\}",
        max_rounds: int = 15,
    ) -> Tuple[bool, Optional[str], List[Dict[str, Any]]]:
        """Unified entry point for solving a CTF challenge (Requirement 4.1).

        Creates/resets blackboard and session, then runs the multi-agent loop.

        Args:
            target_url: Target URL to solve. If None, uses self.target_url.
            flag_format: Regex pattern for flag format.
            max_rounds: Maximum number of collaboration rounds.

        Returns:
            Tuple of (found: bool, flag: Optional[str], action_log: List[Dict])
        """
        # Use provided target_url or fall back to instance target
        url = (target_url or self.target_url).rstrip("/")

        # Reset/reinitialize blackboard for a fresh solve
        self.blackboard = WebStateBlackboard(target_url=url, flag_format=flag_format)

        # Create a fresh session
        session = requests.Session()

        # Reinitialize agents with fresh blackboard and session
        self.coordinator = CoordinatorAgent(
            self.blackboard, session=session, max_rounds=max_rounds
        )
        self.recon = ReconAgent(self.blackboard, url, session=session)
        self.exploit = ExploitAgent(self.blackboard, url, session=session)
        self.critic = CriticAgent(self.blackboard, session=session)

        # Update instance state
        self.target_url = url
        self.flag_format = flag_format

        # Run the collaboration loop
        return self.run_loop(max_rounds=max_rounds)

    def get_state_summary(self) -> Dict[str, Any]:
        """Get current state summary for diagnostics."""
        return {
            "blackboard": self.blackboard.state_summary(),
            "coordinator": {
                "current_round": self.coordinator.current_round,
                "route_attempts": self.coordinator.route_attempts,
                "route_failures": self.coordinator.route_failures,
                "budget_remaining": self.coordinator.budget_remaining,
            },
        }
