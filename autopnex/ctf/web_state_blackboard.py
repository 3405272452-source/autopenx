"""WebStateBlackboard — structured state tracking for CTF Web Agent.

Replaces message-history-based state with typed records that survive
context compression. Every tool result auto-extracts structured summaries
into the blackboard so the Coordinator and PromptCompiler can operate on
compact, queryable state rather than raw LLM history.

Design principle: state lives on the blackboard, not in the prompt.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlsplit

log = logging.getLogger("autopnex.ctf.web_state_blackboard")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RouteStatus(Enum):
    UNTRIED = "untried"
    EXPLORING = "exploring"
    EVIDENCE_FOUND = "evidence_found"
    EXPLOITING = "exploiting"
    SUCCEEDED = "succeeded"
    EXHAUSTED = "exhausted"
    BLOCKED = "blocked"


class EvidenceStrength(Enum):
    WEAK = 0.3
    MODERATE = 0.6
    STRONG = 0.8
    CONFIRMED = 0.95


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EndpointRecord:
    path: str
    methods: List[str] = field(default_factory=lambda: ["GET"])
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    discovered_from: str = ""
    last_seen: float = 0.0
    has_forms: bool = False
    has_links: bool = False
    notable_headers: Dict[str, str] = field(default_factory=dict)
    snippet: str = ""  # Key text excerpt (< 300 chars)

    def __post_init__(self):
        if not self.last_seen:
            self.last_seen = time.time()

    def fingerprint(self) -> str:
        return f"{self.path}|{','.join(sorted(self.methods))}"


@dataclass
class FormRecord:
    action: str
    method: str = "POST"
    fields: List[Dict[str, str]] = field(default_factory=list)
    csrf_field: str = ""
    auth_related: bool = False
    found_on: str = ""
    enctype: str = ""


@dataclass
class ParamRecord:
    name: str
    locations: List[str] = field(default_factory=list)  # query, body, cookie, path
    suspected_routes: List[str] = field(default_factory=list)  # lfi, sqli, ssti, ...
    reflection_count: int = 0
    mutation_history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class EvidenceCard:
    route: str
    score: float
    source: str  # tool that produced it
    observation: str
    request_id: str = ""
    next_hint: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttemptRecord:
    route: str
    tool: str
    args_hash: str
    success: bool
    result_summary: str = ""
    failure_reason: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


@dataclass
class CandidateFlag:
    value: str
    source: str
    confidence: float = 0.5
    verified: bool = False
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


# ---------------------------------------------------------------------------
# WebStateBlackboard
# ---------------------------------------------------------------------------

class WebStateBlackboard:
    """Central structured state for CTF Web challenge solving.

    Every read/write is explicit. The Coordinator reads the blackboard to
    decide what to do next; tool results update the blackboard automatically.
    """

    def __init__(self, target_url: str, challenge_type: str = "web", flag_format: str = r"[A-Za-z0-9_]+\{[^}]+\}"):
        self.target_url = target_url.rstrip("/")
        self.challenge_type = challenge_type
        self.flag_format = flag_format
        self._flag_re = re.compile(flag_format, re.I)

        # Core state
        self.tech_stack: List[str] = []
        self.fingerprints: Dict[str, str] = {}
        self.server_header: str = ""

        # Records
        self.endpoints: Dict[str, EndpointRecord] = {}     # path -> record
        self.forms: List[FormRecord] = []
        self.params: Dict[str, ParamRecord] = {}            # param_name -> record
        self.cookies: Dict[str, str] = {}
        self.csrf_tokens: Dict[str, str] = {}               # page -> token_value

        # Routes
        self.route_status: Dict[str, RouteStatus] = {}
        self.evidence: List[EvidenceCard] = []
        self.hypotheses: List[Dict[str, Any]] = []
        self.attempts: List[AttemptRecord] = []
        self.candidate_flags: List[CandidateFlag] = []

        # Meta
        self.round: int = 0
        self.rounds_since_last_evidence: int = 0
        self.blockers: List[str] = []
        self.created_at: float = time.time()

    # ------------------------------------------------------------------
    # Endpoint management
    # ------------------------------------------------------------------

    def record_endpoint(
        self,
        path: str,
        method: str = "GET",
        status_code: int = 0,
        content_type: str = "",
        content_length: int = 0,
        discovered_from: str = "",
        headers: Optional[Dict[str, str]] = None,
        body_snippet: str = "",
    ) -> EndpointRecord:
        """Record or update an endpoint."""
        normalized = self._normalize_path(path)
        if normalized in self.endpoints:
            ep = self.endpoints[normalized]
            if method not in ep.methods:
                ep.methods.append(method)
            ep.status_code = status_code
            ep.last_seen = time.time()
            if content_length:
                ep.content_length = content_length
            if body_snippet:
                ep.snippet = body_snippet[:300]
            if headers:
                for k, v in headers.items():
                    if k.lower() in ("server", "x-powered-by", "set-cookie", "location", "x-flag"):
                        ep.notable_headers[k] = v
            return ep

        ep = EndpointRecord(
            path=normalized,
            methods=[method],
            status_code=status_code,
            content_type=content_type,
            content_length=content_length,
            discovered_from=discovered_from,
            last_seen=time.time(),
            snippet=body_snippet[:300],
        )
        if headers:
            for k, v in headers.items():
                if k.lower() in ("server", "x-powered-by", "set-cookie", "location", "x-flag"):
                    ep.notable_headers[k] = v
        self.endpoints[normalized] = ep

        # Auto-detect tech stack from headers
        self._extract_tech_from_headers(headers or {})
        return ep

    def get_endpoint(self, path: str) -> Optional[EndpointRecord]:
        return self.endpoints.get(self._normalize_path(path))

    def list_endpoints(self, status_filter: Optional[int] = None) -> List[EndpointRecord]:
        result = list(self.endpoints.values())
        if status_filter is not None:
            result = [e for e in result if e.status_code == status_filter]
        result.sort(key=lambda e: e.last_seen, reverse=True)
        return result

    # ------------------------------------------------------------------
    # Form management
    # ------------------------------------------------------------------

    def record_form(
        self,
        action: str,
        method: str = "POST",
        fields: Optional[List[Dict[str, str]]] = None,
        csrf_field: str = "",
        auth_related: bool = False,
        found_on: str = "",
        enctype: str = "",
    ) -> FormRecord:
        fr = FormRecord(
            action=action,
            method=method.upper(),
            fields=fields or [],
            csrf_field=csrf_field,
            auth_related=auth_related,
            found_on=found_on,
            enctype=enctype,
        )
        # Dedup
        existing = [f for f in self.forms if f.action == action and f.method == method.upper()]
        if not existing:
            self.forms.append(fr)
        return fr

    def get_login_form(self) -> Optional[FormRecord]:
        for f in self.forms:
            if f.auth_related:
                return f
            field_names = [fd.get("name", "") for fd in f.fields]
            if "username" in field_names or "password" in field_names or "user" in field_names:
                return f
        return None

    # ------------------------------------------------------------------
    # Parameter management
    # ------------------------------------------------------------------

    def record_param(
        self,
        name: str,
        location: str = "query",
        suspected_route: str = "",
    ) -> ParamRecord:
        if name in self.params:
            p = self.params[name]
            if location not in p.locations:
                p.locations.append(location)
            if suspected_route and suspected_route not in p.suspected_routes:
                p.suspected_routes.append(suspected_route)
            return p

        p = ParamRecord(
            name=name,
            locations=[location],
            suspected_routes=[suspected_route] if suspected_route else [],
        )
        self.params[name] = p
        return p

    def get_interesting_params(self) -> List[ParamRecord]:
        """Return params that hint at specific attack routes."""
        interesting = []
        for name, p in self.params.items():
            # If param already has suspected routes (explicitly set), include it
            if p.suspected_routes:
                interesting.append(p)
                continue
            # Check name-based hints
            lname = name.lower()
            if any(kw in lname for kw in ("file", "page", "path", "template", "include", "view")):
                if "lfi" not in p.suspected_routes:
                    p.suspected_routes.append("lfi")
                interesting.append(p)
            elif any(kw in lname for kw in ("id", "user", "item", "cat", "q", "search", "query")):
                if "sqli" not in p.suspected_routes:
                    p.suspected_routes.append("sqli")
                # q/search/query are also prime XSS reflection points
                if "xss" not in p.suspected_routes:
                    p.suspected_routes.append("xss")
                interesting.append(p)
            elif any(kw in lname for kw in ("cmd", "exec", "command", "shell", "ping", "ip", "host")):
                if "cmdi" not in p.suspected_routes:
                    p.suspected_routes.append("cmdi")
                interesting.append(p)
            elif any(kw in lname for kw in ("url", "uri", "redirect", "link", "proxy")):
                if "ssrf" not in p.suspected_routes:
                    p.suspected_routes.append("ssrf")
                interesting.append(p)
            elif any(kw in lname for kw in ("msg", "text", "message", "comment", "content", "name", "template", "post")):
                if "ssti" not in p.suspected_routes:
                    p.suspected_routes.append("ssti")
                # message/comment/content/name/text/post are also common XSS params
                if "xss" not in p.suspected_routes:
                    p.suspected_routes.append("xss")
                interesting.append(p)
            elif any(kw in lname for kw in ("upload", "file")):
                if "upload" not in p.suspected_routes:
                    p.suspected_routes.append("upload")
                interesting.append(p)
        return interesting

    # ------------------------------------------------------------------
    # Auth / Session
    # ------------------------------------------------------------------

    def record_cookie(self, name: str, value: str) -> None:
        self.cookies[name] = value

    def record_cookies_from_headers(self, headers: Dict[str, str]) -> None:
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                parts = v.split(";")[0].split("=", 1)
                if len(parts) == 2:
                    self.cookies[parts[0].strip()] = parts[1].strip()

    def record_csrf_token(self, page: str, token: str) -> None:
        self.csrf_tokens[page] = token

    def get_latest_csrf(self) -> Optional[str]:
        return list(self.csrf_tokens.values())[-1] if self.csrf_tokens else None

    # ------------------------------------------------------------------
    # Route management
    # ------------------------------------------------------------------

    def set_route_status(self, route: str, status: RouteStatus) -> None:
        self.route_status[route] = status

    def get_route_status(self, route: str) -> RouteStatus:
        return self.route_status.get(route, RouteStatus.UNTRIED)

    def get_active_routes(self) -> List[str]:
        """Routes with evidence but not yet succeeded or exhausted."""
        active = []
        for route, status in self.route_status.items():
            if status in (RouteStatus.EVIDENCE_FOUND, RouteStatus.EXPLORING, RouteStatus.EXPLOITING):
                active.append(route)
        # Sort by evidence score
        active.sort(key=lambda r: self._route_evidence_score(r), reverse=True)
        return active

    def _route_evidence_score(self, route: str) -> float:
        cards = [c for c in self.evidence if c.route == route]
        return sum(c.score for c in cards) if cards else 0.0

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(
        self,
        route: str,
        score: float,
        source: str,
        observation: str,
        next_hint: str = "",
    ) -> EvidenceCard:
        card = EvidenceCard(
            route=route,
            score=score,
            source=source,
            observation=observation[:500],
            next_hint=next_hint,
            timestamp=time.time(),
        )
        self.evidence.append(card)
        self.rounds_since_last_evidence = 0

        # Auto-promote route status
        current = self.get_route_status(route)
        if current in (RouteStatus.UNTRIED, RouteStatus.EXPLORING):
            if score >= 0.7:
                self.set_route_status(route, RouteStatus.EVIDENCE_FOUND)
            else:
                self.set_route_status(route, RouteStatus.EXPLORING)

        return card

    def top_evidence(self, limit: int = 5) -> List[EvidenceCard]:
        return sorted(self.evidence, key=lambda c: c.score, reverse=True)[:limit]

    def has_strong_evidence(self, route: str) -> bool:
        return any(c.route == route and c.score >= 0.7 for c in self.evidence)

    def get_top_routes(self, k: int = 5) -> List[str]:
        """Return top-k routes sorted by descending maximum evidence score.

        Each route's score is its highest individual evidence card score.
        Returns at most k routes.
        """
        route_max: Dict[str, float] = {}
        for card in self.evidence:
            if card.route not in route_max or card.score > route_max[card.route]:
                route_max[card.route] = card.score
        sorted_routes = sorted(route_max.keys(), key=lambda r: route_max[r], reverse=True)
        return sorted_routes[:k]

    # ------------------------------------------------------------------
    # Attempts (with dedup)
    # ------------------------------------------------------------------

    def record_attempt(
        self,
        route: str,
        tool: str,
        args: Dict[str, Any],
        success: bool,
        result_summary: str = "",
        failure_reason: str = "",
    ) -> AttemptRecord:
        args_hash = self._hash_args(tool, args)

        # Check if already attempted
        for a in self.attempts:
            if a.tool == tool and a.args_hash == args_hash:
                log.debug("Duplicate attempt blocked: %s %s", tool, args_hash[:12])
                return a

        record = AttemptRecord(
            route=route,
            tool=tool,
            args_hash=args_hash,
            success=success,
            result_summary=result_summary[:300],
            failure_reason=failure_reason[:200],
            timestamp=time.time(),
        )
        self.attempts.append(record)

        # Auto-classify failure
        if not success and not failure_reason:
            record.failure_reason = "no_flag_found"

        return record

    def has_tried(self, tool: str, args: Dict[str, Any]) -> bool:
        h = self._hash_args(tool, args)
        return any(a.tool == tool and a.args_hash == h for a in self.attempts)

    def failed_count(self, route: str = "") -> int:
        if route:
            return sum(1 for a in self.attempts if a.route == route and not a.success)
        return sum(1 for a in self.attempts if not a.success)

    def recent_failures(self, count: int = 5) -> List[AttemptRecord]:
        fails = [a for a in self.attempts if not a.success]
        fails.sort(key=lambda a: a.timestamp, reverse=True)
        return fails[:count]

    # ------------------------------------------------------------------
    # Flag candidates
    # ------------------------------------------------------------------

    def add_flag_candidate(self, value: str, source: str, confidence: float = 0.5) -> CandidateFlag:
        # Dedup
        for cf in self.candidate_flags:
            if cf.value == value:
                return cf
        cf = CandidateFlag(value=value, source=source, confidence=confidence)
        self.candidate_flags.append(cf)
        return cf

    def check_and_record_flag(self, text: str, source: str = "") -> Optional[str]:
        """Check text for flag pattern and record if found."""
        if not text:
            return None
        match = self._flag_re.search(text)
        if match:
            flag_val = match.group(0)
            self.add_flag_candidate(flag_val, source, confidence=0.9)
            return flag_val
        return None

    def get_unverified_flags(self) -> List[CandidateFlag]:
        return [cf for cf in self.candidate_flags if not cf.verified]

    # ------------------------------------------------------------------
    # Tool result auto-extraction
    # ------------------------------------------------------------------

    def ingest_tool_result(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        result: Dict[str, Any],
        route_hint: str = "",
    ) -> Dict[str, Any]:
        """Automatically extract structured state from any tool result.

        Call this after every tool execution to keep the blackboard current.
        Returns a summary dict suitable for the PromptCompiler.
        """
        self.round += 1

        # Extract endpoints from HTTP results
        path = tool_args.get("path", "") or tool_args.get("url", "")
        method = tool_args.get("method", "GET")

        if result.get("status_code"):
            self.record_endpoint(
                path=path,
                method=method,
                status_code=result.get("status_code", 0),
                content_type=result.get("headers", {}).get("content-type", ""),
                content_length=len(result.get("body", "") or result.get("content", "") or ""),
                headers=self._safe_headers(result.get("headers", {})),
                body_snippet=(result.get("body") or result.get("content") or "")[:300],
            )

        # Extract cookies
        if result.get("headers"):
            self.record_cookies_from_headers(self._safe_headers(result["headers"]))

        # Extract params from args
        for key in ("params", "data", "json"):
            params_dict = tool_args.get(key, {})
            if isinstance(params_dict, dict):
                for pname in params_dict:
                    loc = {"params": "query", "data": "body", "json": "body"}.get(key, "query")
                    self.record_param(pname, location=loc, suspected_route=route_hint)

        # Extract forms from body
        body = result.get("body", "") or result.get("content", "") or ""
        if isinstance(body, str) and "<form" in body.lower():
            self._extract_forms_from_html(body, path)

        # Extract server/framework fingerprint
        if result.get("headers"):
            headers = self._safe_headers(result["headers"])
            self._extract_tech_from_headers(headers)

        # Check for flag in result
        flag = self.check_and_record_flag(
            body if isinstance(body, str) else str(body)[:5000],
            source=tool_name,
        )
        if flag:
            self.add_evidence(
                route="direct_flag",
                score=0.99,
                source=tool_name,
                observation=f"Flag found: {flag}",
            )

        # Build summary
        return self.state_summary()

    # ------------------------------------------------------------------
    # State Summary (for PromptCompiler)
    # ------------------------------------------------------------------

    def state_summary(self) -> Dict[str, Any]:
        """Generate a compact state summary suitable for prompt injection."""
        return {
            "tech_stack": self.tech_stack or ["unknown"],
            "server": self.server_header or "unknown",
            "endpoint_count": len(self.endpoints),
            "key_endpoints": [
                {
                    "path": e.path,
                    "status": e.status_code,
                    "methods": e.methods,
                    "snippet": e.snippet[:100],
                }
                for e in self.list_endpoints()
                if e.status_code in (200, 302, 401, 403) or e.has_forms
            ][:12],
            "forms": [
                {"action": f.action, "method": f.method, "fields": [fd.get("name") for fd in f.fields], "auth": f.auth_related}
                for f in self.forms[:8]
            ],
            "interesting_params": [
                {"name": p.name, "locations": p.locations, "suspected_routes": p.suspected_routes}
                for p in self.get_interesting_params()[:10]
            ],
            "cookies": list(self.cookies.keys()),
            "csrf_present": len(self.csrf_tokens) > 0,
            "active_routes": self.get_active_routes(),
            "route_status": {k: v.value for k, v in self.route_status.items()},
            "top_evidence": [e.to_dict() for e in self.top_evidence(5)],
            "total_attempts": len(self.attempts),
            "failed_attempts": self.failed_count(),
            "recent_failures": [
                {"route": a.route, "tool": a.tool, "reason": a.failure_reason}
                for a in self.recent_failures(5)
            ],
            "candidate_flags": len(self.candidate_flags),
            "blockers": self.blockers,
            "round": self.round,
            "rounds_since_evidence": self.rounds_since_last_evidence,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        data = {
            "target_url": self.target_url,
            "challenge_type": self.challenge_type,
            "tech_stack": self.tech_stack,
            "fingerprints": self.fingerprints,
            "server_header": self.server_header,
            "endpoints": {k: asdict(v) for k, v in self.endpoints.items()},
            "forms": [asdict(f) for f in self.forms],
            "params": {k: asdict(v) for k, v in self.params.items()},
            "route_status": {k: v.value for k, v in self.route_status.items()},
            "evidence": [e.to_dict() for e in self.evidence],
            "attempts": [asdict(a) for a in self.attempts],
            "candidate_flags": [asdict(cf) for cf in self.candidate_flags],
            "blockers": self.blockers,
            "round": self.round,
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def save(self, path: str) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_path(path: str) -> str:
        if not path:
            return "/"
        if path.startswith(("http://", "https://")):
            parsed = urlsplit(path)
            path = parsed.path or "/"
        return path if path.startswith("/") else "/" + path

    @staticmethod
    def _safe_headers(headers: Any) -> Dict[str, str]:
        if isinstance(headers, dict):
            return {str(k): str(v) for k, v in headers.items()}
        return {}

    @staticmethod
    def _hash_args(tool: str, args: Dict[str, Any]) -> str:
        canonical = json.dumps(args, sort_keys=True, default=str)
        return hashlib.sha256(f"{tool}|{canonical}".encode()).hexdigest()[:16]

    def _extract_tech_from_headers(self, headers: Dict[str, str]) -> None:
        server = headers.get("server") or headers.get("Server") or headers.get("x-powered-by") or headers.get("X-Powered-By") or ""
        if server and server not in self.tech_stack:
            self.tech_stack.append(server)
            self.server_header = server or self.server_header
        # PHP detection
        if "php" in str(headers).lower() and "PHP" not in self.tech_stack:
            self.tech_stack.append("PHP")
        # Framework from Set-Cookie
        for v in headers.values():
            v_lower = str(v).lower()
            if "laravel_session" in v_lower and "Laravel" not in self.tech_stack:
                self.tech_stack.append("Laravel")
            if "phpsessid" in v_lower and "PHP" not in self.tech_stack:
                self.tech_stack.append("PHP")

    def _extract_forms_from_html(self, html: str, page_url: str) -> None:
        try:
            from .web_session import FormExtractor
            forms = FormExtractor.extract(html, base_url=page_url or "/")
            for form in forms[:5]:
                fields = [{"name": f.name, "type": f.type, "value": f.value} for f in form.fields]
                csrf = ""
                for f in form.fields:
                    if "csrf" in f.name.lower() or "token" in f.name.lower():
                        csrf = f.value or f.name
                        self.record_csrf_token(page_url, csrf)
                auth = any(
                    n in [fd.get("name", "") for fd in fields]
                    for n in ("username", "password", "user", "pass", "login")
                )
                self.record_form(
                    action=form.action or page_url,
                    method=form.method or "POST",
                    fields=fields,
                    csrf_field=csrf,
                    auth_related=auth,
                    found_on=page_url,
                    enctype=form.enctype or "",
                )
        except Exception:
            pass  # Non-critical extraction
