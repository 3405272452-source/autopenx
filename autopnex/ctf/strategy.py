"""CTF Strategy Layer - evidence scoring, budget control, deduplication, route switching.

Provides the agent with "strategy awareness" so it does not blindly repeat
the same payload or route indefinitely.  Key responsibilities:

* Evidence scoring – rank how promising each tool result is.
* Action deduplication – skip exact (tool, args) replays.
* Route budget – cap attempts per attack vector.
* Adjacent route suggestion – when a route is exhausted, propose the next one.
* Cost tracking – lightweight accounting so the agent knows when to stop.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("autopnex.ctf.strategy")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """A single piece of evidence from a tool execution."""

    tool: str
    args: Dict[str, Any]
    result: Dict[str, Any]
    score: float = 0.0          # 0.0–1.0, higher = more promising
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "score": round(self.score, 3),
            "tags": self.tags,
            "args_preview": str(self.args)[:200],
        }


@dataclass
class RouteBudget:
    """Budget tracking for a specific attack route."""

    route_id: str               # e.g. "lfi", "ssti", "sqli", "jwt"
    max_attempts: int = 5
    attempts: int = 0
    best_score: float = 0.0
    exhausted: bool = False
    last_evidence: Optional[Evidence] = None

    def can_attempt(self) -> bool:
        return not self.exhausted and self.attempts < self.max_attempts

    def record_attempt(self, evidence: Evidence) -> None:
        self.attempts += 1
        if evidence.score > self.best_score:
            self.best_score = evidence.score
            self.last_evidence = evidence
        if self.attempts >= self.max_attempts:
            self.exhausted = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "best_score": round(self.best_score, 3),
            "exhausted": self.exhausted,
        }


# ---------------------------------------------------------------------------
# Strategy Engine
# ---------------------------------------------------------------------------

class StrategyEngine:
    """Central strategy engine for CTF agent decision making."""

    # Cost tiers (abstract units, not dollars)
    COST_LIGHT = 1
    COST_MEDIUM = 3
    COST_HEAVY = 10

    COST_MAP: Dict[str, int] = {
        "http_request": COST_LIGHT,
        "scan_flag": COST_LIGHT,
        "decode_data": COST_LIGHT,
        "file_analyze": COST_LIGHT,
        "ctf_knowledge_search": COST_LIGHT,
        "run_python": COST_MEDIUM,
        "run_tool_script": COST_MEDIUM,
        "write_tool_script": COST_MEDIUM,
        "download_tool_url": COST_MEDIUM,
        "install_python_package": COST_HEAVY,
    }

    # Default route order for Web CTF (most likely → least likely)
    DEFAULT_WEB_ROUTES: List[str] = [
        "source_hint",      # source code / attachment clues
        "lfi",              # local file inclusion / path traversal
        "sqli",             # SQL injection
        "ssti",             # server-side template injection
        "php_pop",          # PHP deserialization / POP chain
        "cmdi",             # command injection
        "upload",           # file upload
        "jwt",              # JWT manipulation
        "ssrf",             # server-side request forgery
        "xxe",              # XML external entity
        "idor",             # insecure direct object reference
        "nosqli",           # NoSQL injection (MongoDB/Redis)
        "xss",              # cross-site scripting
        "direnum",          # directory enumeration
        "crypto_param",     # crypto / encoded parameter
        "brute_force",      # credential brute force
    ]

    def __init__(
        self,
        max_total_cost: int = 50,
        max_iterations: int = 15,
        helper_budget_per_route: int = 3,
        route_order: Optional[List[str]] = None,
    ):
        self.max_total_cost = max_total_cost
        self.max_iterations = max_iterations
        self.helper_budget_per_route = helper_budget_per_route
        self.route_order = route_order or list(self.DEFAULT_WEB_ROUTES)

        self._evidence: List[Evidence] = []
        self._routes: Dict[str, RouteBudget] = {}
        self._attempted_hashes: Set[str] = set()
        self._total_cost = 0
        self._current_route: Optional[str] = None
        self._route_index = 0

    # -- public API --------------------------------------------------------

    def record_tool_result(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Evidence:
        """Record a tool result, score it, track cost, and enforce dedup."""
        evidence = self._score_evidence(tool_name, tool_args, tool_result)
        self._evidence.append(evidence)

        # Cost tracking
        cost = self.COST_MAP.get(tool_name, self.COST_LIGHT)
        self._total_cost += cost

        # Deduplication
        args_hash = self._hash_args(tool_name, tool_args)
        self._attempted_hashes.add(args_hash)

        # Route budget
        if self._current_route:
            route = self._routes.setdefault(
                self._current_route,
                RouteBudget(route_id=self._current_route, max_attempts=self.helper_budget_per_route),
            )
            route.record_attempt(evidence)

        return evidence

    def should_attempt(self, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        """Return False if this exact (tool, args) combo was already tried."""
        return self._hash_args(tool_name, tool_args) not in self._attempted_hashes

    def set_route(self, route_id: str) -> None:
        """Switch the active attack route."""
        if route_id == self._current_route:
            return
        log.info("Strategy route switched: %s → %s", self._current_route, route_id)
        self._current_route = route_id
        if route_id not in self._routes:
            self._routes[route_id] = RouteBudget(
                route_id=route_id,
                max_attempts=self.helper_budget_per_route,
            )
        # Update route index so suggest_next_route starts from here
        if route_id in self.route_order:
            self._route_index = self.route_order.index(route_id)

    def can_continue_route(self, route_id: Optional[str] = None) -> bool:
        """Check whether the given (or current) route still has budget."""
        rid = route_id or self._current_route
        if not rid:
            return True
        budget = self._routes.get(rid)
        if not budget:
            return True
        return budget.can_attempt()

    def is_budget_exhausted(self) -> bool:
        """Check whether the global cost budget is exhausted."""
        return self._total_cost >= self.max_total_cost

    def suggest_next_route(self) -> Optional[str]:
        """Suggest the next route when the current one is exhausted.

        Prefers routes that have not been exhausted and have the highest
        potential based on current evidence.
        """
        # 1. Try next route in order that is not exhausted
        for i in range(self._route_index + 1, len(self.route_order)):
            rid = self.route_order[i]
            route = self._routes.get(rid)
            if route is None or route.can_attempt():
                return rid

        # 2. Fall back to any route with remaining budget
        for rid in self.route_order:
            route = self._routes.get(rid)
            if route is None or route.can_attempt():
                return rid

        return None

    def get_summary(self) -> Dict[str, Any]:
        """Return a concise summary for LLM consumption or event emission."""
        return {
            "total_cost": self._total_cost,
            "max_cost": self.max_total_cost,
            "current_route": self._current_route,
            "routes": {k: v.to_dict() for k, v in self._routes.items()},
            "evidence_count": len(self._evidence),
            "best_evidence": self._best_evidence(),
            "budget_exhausted": self.is_budget_exhausted(),
        }

    def emit_if_route_exhausted(self) -> Optional[Dict[str, Any]]:
        """If the current route just became exhausted, return a switch suggestion."""
        if not self._current_route:
            return None
        route = self._routes.get(self._current_route)
        if route and route.exhausted:
            next_route = self.suggest_next_route()
            if next_route:
                return {
                    "event": "route_switch",
                    "from": self._current_route,
                    "to": next_route,
                    "reason": "budget_exhausted",
                }
        return None

    # -- route inference --------------------------------------------------

    def infer_route(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> str:
        """Infer the current attack route from tool execution context."""
        url = str(tool_args.get("url", ""))
        lowered_url = url.lower()
        body = str(tool_result.get("body", "")).lower()
        param_keys = " ".join(str(k).lower() for k in tool_args.get("params", {}).keys())
        param_keys += " ".join(str(k).lower() for k in tool_args.get("form", {}).keys())
        payload = str(tool_args.get("data", "") or tool_args.get("json", "") or "").lower()

        # Parameter-based route hints
        if any(p in lowered_url for p in ("cmd=", "exec=", "command=", "shell=", "ping=")):
            return "cmdi"
        if any(p in lowered_url for p in ("url=", "uri=", "redirect=", "link=", "href=")):
            return "ssrf"
        if any(p in lowered_url for p in ("file=", "path=", "page=", "include=", "template=", "view=", "filename=")):
            return "lfi"
        if any(p in lowered_url for p in ("id=", "item=", "cat=", "category=", "product=", "user=")):
            return "sqli"
        if any(p in lowered_url for p in ("name=", "template=", "message=", "content=", "text=")):
            return "ssti"
        if "pop=" in lowered_url or "unserialize" in body:
            return "php_pop"
        if "jwt" in body or "eyj" in payload or "authorization" in body:
            return "jwt"
        if "xml" in body or "<!doctype" in payload or "xxe" in lowered_url:
            return "xxe"
        if "upload" in lowered_url or tool_name in ("write_tool_script", "run_tool_script"):
            # If the tool writes/runs exploit scripts, check payload for upload hints
            if "file" in payload or "upload" in payload:
                return "upload"
        if any(p in lowered_url for p in ("user_id=", "uid=", "order_id=", "doc_id=")):
            return "idor"

        # NoSQLi route hints
        if any(p in lowered_url for p in ("login", "auth", "filter=")):
            if any(h in body for h in ("mongo", "mongodb", "bson", "objectid", "redis", "nosql")):
                return "nosqli"
        if "$gt" in payload or "$ne" in payload or "$regex" in payload:
            return "nosqli"

        # XSS route hints
        if any(p in lowered_url for p in ("q=", "search=", "query=", "comment=", "message=")):
            if any(h in body for h in ("<script", "onerror=", "onload=", "alert(")):
                return "xss"

        # DirEnum route hints
        if any(p in lowered_url for p in ("/admin", "/hidden", "/secret", "/backup", "/flag")):
            return "direnum"

        # Tool-based route hints
        if tool_name in ("lfi_detect", "file_analyze"):
            return "lfi"
        if tool_name in ("sql_inject", "sqli_detect"):
            return "sqli"
        if tool_name in ("ssti_detect", "template_probe"):
            return "ssti"
        if tool_name == "unserialize_detect":
            return "php_pop"
        if tool_name == "phar_pdo_chain":
            return "php_pop"
        if tool_name in ("jwt_decode", "jwt_forge"):
            return "jwt"
        if tool_name in ("xxe_probe", "xml_inject"):
            return "xxe"
        if tool_name == "idor_probe":
            return "idor"

        # Result body-based fallback
        if any(k in body for k in ("sqlstate", "syntax error", "mysql", "sqlite", "unclosed quotation")):
            return "sqli"
        if "49" in body and "{{" in str(tool_args.get("params", {})).lower():
            return "ssti"
        if re.search(r'[A-Za-z0-9_]+\{[^}]+\}', body):
            # If flag found, stay on whatever route we think we're on; if unknown, prefer source_hint
            return self._current_route or "source_hint"

        return "unknown"

    # -- scoring -----------------------------------------------------------

    def _score_evidence(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Evidence:
        """Score a tool result based on heuristics."""
        score = 0.0
        tags: List[str] = []

        # HTTP-specific signals
        if tool_name == "http_request":
            status = tool_result.get("status_code", 0)
            if status == 200:
                score += 0.3
                tags.append("ok_200")
            elif status == 302:
                score += 0.2
                tags.append("redirect_302")
            elif status == 500:
                score += 0.5
                tags.append("error_500")
            elif status in (403, 401):
                score += 0.1
                tags.append("auth_barrier")

            body = str(tool_result.get("body", ""))
            lowered = body.lower()
            if any(k in lowered for k in ("correct", "success", "welcome", "flag is")) or re.search(r'[a-z0-9_]+\{', lowered):
                score += 0.6
                tags.append("flag_indicator")
            if any(k in lowered for k in ("sql", "mysql", "sqlite", "odbc", "syntax error", "warning")):
                score += 0.4
                tags.append("sql_leakage")
            if any(k in lowered for k in ("eval", "exec", "system", "popen", "shell_exec")):
                score += 0.4
                tags.append("code_execution_hint")
            if "not found" in lowered or "404" in lowered:
                score -= 0.1
                tags.append("not_found")

        # Detection tools
        elif tool_name in ("lfi_detect", "ssti_detect", "unserialize_detect", "sql_inject"):
            if tool_result.get("detected") or tool_result.get("vulnerable"):
                score += 0.85
                tags.append("vulnerability_confirmed")
            if tool_result.get("confirmed"):
                score += 0.9
                tags.append("exploitable")

        # Python execution
        elif tool_name == "run_python":
            if tool_result.get("success"):
                stdout = str(tool_result.get("stdout", ""))
                if re.search(r'[A-Za-z0-9_]+\{[^}]+\}', stdout):
                    score += 1.0
                    tags.append("flag_in_stdout")

        # File analysis
        elif tool_name == "file_analyze":
            if tool_result.get("interesting_strings"):
                score += 0.3
                tags.append("interesting_strings")

        # Knowledge search
        elif tool_name == "ctf_knowledge_search":
            results = tool_result.get("results", [])
            if len(results) > 0:
                score += 0.1 * min(len(results), 5)
                tags.append("knowledge_hit")

        # Flag scan
        elif tool_name == "scan_flag":
            if tool_result.get("flags_found"):
                score += 1.0
                tags.append("flag_found")

        score = max(0.0, min(score, 1.0))
        return Evidence(
            tool=tool_name,
            args=tool_args,
            result=tool_result,
            score=score,
            tags=tags,
        )

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _hash_args(tool_name: str, tool_args: Dict[str, Any]) -> str:
        """Deterministic short hash of (tool, args) for deduplication."""
        payload = json.dumps({"tool": tool_name, "args": tool_args}, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def _best_evidence(self) -> Optional[Dict[str, Any]]:
        if not self._evidence:
            return None
        best = max(self._evidence, key=lambda e: e.score)
        return best.to_dict()
