"""Shared HTTP helpers for tool implementations."""
from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from config.settings import RuntimeConfig, settings

log = logging.getLogger("autopnex.http")

# ---------------------------------------------------------------------------
# Global authenticated session shared by all tools
# ---------------------------------------------------------------------------
_global_session: Optional[requests.Session] = None
_session_cookies: Dict[str, str] = {}
_session_headers: Dict[str, str] = {}


def get_session() -> Optional[requests.Session]:
    """Return the global authenticated session, or None if not logged in."""
    return _global_session


def get_session_cookies() -> Dict[str, str]:
    """Return cookies from the authenticated session."""
    return dict(_session_cookies)


def get_session_headers() -> Dict[str, str]:
    """Return extra headers from the authenticated session."""
    return dict(_session_headers)


def login_before_scan(
    target: str,
    login_endpoint: str = "/login.php",
    username_field: str = "username",
    password_field: str = "password",
    credentials_list: Optional[List[Tuple[str, str]]] = None,
    csrf_field: Optional[str] = None,
    success_indicators: Optional[List[str]] = None,
    failure_indicators: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Attempt form-based login against the target. Stores session cookies globally.

    Returns (success, message).
    """
    global _global_session, _session_cookies, _session_headers

    if credentials_list is None:
        credentials_list = [
            ("admin", "password"),
            ("admin", "admin"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
        ]

    if success_indicators is None:
        success_indicators = ["logout", "dashboard", "welcome", "admin", "security"]
    if failure_indicators is None:
        failure_indicators = ["login failed", "incorrect", "invalid", "wrong", "error"]

    base = normalise_target(target)
    login_url = base.rstrip("/") + login_endpoint

    for uname, passwd in credentials_list:
        session = requests.Session()
        session.verify = False
        session.headers.update(_default_headers())

        # First GET the login page to obtain any CSRF token / session cookie
        try:
            login_page = session.get(login_url, timeout=settings.effective().http_timeout, allow_redirects=True)
        except requests.RequestException as exc:
            log.debug("login GET failed: %s", exc)
            continue

        # Try to extract CSRF token from login page
        csrf_token = ""
        if csrf_field:
            body = login_page.text or ""
            # Try common CSRF patterns
            import re
            for pattern in [
                rf'name=["\']?{re.escape(csrf_field)}["\']?\s+value=["\']?([^"\'>\s]+)',
                rf'value=["\']?([^"\'>\s]+)["\']?\s+name=["\']?{re.escape(csrf_field)}',
                rf'name=["\']?{re.escape(csrf_field)}["\']?[^>]*value=["\']?([^"\'>\s]+)',
            ]:
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    csrf_token = m.group(1)
                    break

        # POST login credentials
        form_data = {username_field: uname, password_field: passwd}
        if csrf_field and csrf_token:
            form_data[csrf_field] = csrf_token

        try:
            resp = session.post(login_url, data=form_data, timeout=settings.effective().http_timeout, allow_redirects=True)
        except requests.RequestException as exc:
            log.debug("login POST failed: %s", exc)
            continue

        body_lower = (resp.text or "").lower()

        # Check success: 200 with success indicators, or redirect away from login
        has_success = any(kw in body_lower for kw in success_indicators)
        has_failure = any(kw in body_lower for kw in failure_indicators)
        redirected_away = resp.url and login_endpoint not in resp.url

        if (has_success and not has_failure) or (redirected_away and not has_failure):
            _global_session = session
            _session_cookies = dict(session.cookies)
            _session_headers = dict(session.headers)
            msg = f"Logged in as {uname}:{passwd} (cookies: {list(_session_cookies.keys())})"
            log.info(msg)
            return True, msg

    _global_session = None
    _session_cookies = {}
    _session_headers = {}
    return False, "All login attempts failed"


def clear_session() -> None:
    """Clear the global authenticated session."""
    global _global_session, _session_cookies, _session_headers
    if _global_session:
        _global_session.close()
    _global_session = None
    _session_cookies = {}
    _session_headers = {}


def _default_headers() -> Dict[str, str]:
    cfg = settings.effective()
    return {
        "User-Agent": cfg.user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }


def normalise_target(target: str) -> str:
    if not target:
        return target
    if "://" not in target:
        target = "http://" + target
    return target.rstrip("/")


def parsed(target: str) -> Tuple[str, str, int]:
    t = normalise_target(target)
    p = urlparse(t)
    scheme = p.scheme or "http"
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    return scheme, host, port


class TargetScopeError(RuntimeError):
    pass


def ensure_target_allowed(target: str, *, runtime_config: Optional[RuntimeConfig] = None) -> str:
    runtime = runtime_config or settings.effective()
    normalised = normalise_target(target)
    host = urlparse(normalised).hostname or ""
    if not host:
        raise TargetScopeError("invalid_target")
    if runtime.allow_local_targets:
        return normalised
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        lowered = host.lower()
        if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(".local"):
            raise TargetScopeError("loopback_targets_require_allow_local_targets")
        return normalised

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
        raise TargetScopeError("private_or_loopback_targets_require_allow_local_targets")
    return normalised


def request(
    method: str,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
    allow_redirects: bool = True,
    json_body: Any = None,
    proxies: Optional[Dict[str, str]] = None,
    use_session: bool = True,
) -> Tuple[Optional[requests.Response], Optional[str], float]:
    """Thin wrapper around requests that never raises — returns (response, error, elapsed).

    When *use_session* is True (default) and a global authenticated session exists,
    the request is made through that session so cookies are automatically included.
    """
    cfg = settings.effective()
    merged_headers = dict(_default_headers())
    if headers:
        merged_headers.update(headers)
    start = time.perf_counter()
    if cfg.request_delay:
        time.sleep(cfg.request_delay)
    try:
        # Use global authenticated session when available
        session = get_session() if use_session else None
        if session is not None:
            resp = session.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json_body,
                headers=merged_headers,
                timeout=timeout or cfg.http_timeout,
                allow_redirects=allow_redirects,
                proxies=proxies,
            )
        else:
            resp = requests.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json_body,
                headers=merged_headers,
                timeout=timeout or cfg.http_timeout,
                allow_redirects=allow_redirects,
                proxies=proxies,
                verify=False,
            )
        return resp, None, time.perf_counter() - start
    except requests.RequestException as exc:
        return None, str(exc), time.perf_counter() - start


# Silence urllib3 InsecureRequestWarning (verify=False) — acceptable for pentest.
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass
