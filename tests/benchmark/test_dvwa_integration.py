"""DVWA Integration Tests — validates RouteStateMachine against live DVWA.

Tests require DVWA running at http://127.0.0.1:8080 with:
  - Credentials: admin / password
  - Security level: Low

Run with:
    pytest tests/benchmark/test_dvwa_integration.py --collect-only
    pytest tests/benchmark/test_dvwa_integration.py -v

Tests are skipped gracefully when DVWA is not reachable.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from autopnex.ctf.route_state_machine import RouteResult, run_route
from autopnex.ctf.web_state_blackboard import WebStateBlackboard


# ---------------------------------------------------------------------------
# DVWA Configuration
# ---------------------------------------------------------------------------

DVWA_BASE_URL = "http://127.0.0.1:8080"
DVWA_USER = "admin"
DVWA_PASS = "password"

# Route → DVWA vulnerability path mapping
DVWA_ROUTES = {
    "sqli": "/vulnerabilities/sqli/",
    "cmdi": "/vulnerabilities/exec/",
    "lfi": "/vulnerabilities/fi/",
    "xss": "/vulnerabilities/xss_r/",
}


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def dvwa_available() -> bool:
    """Check if DVWA is reachable at the expected URL."""
    try:
        resp = requests.get(DVWA_BASE_URL + "/login.php", timeout=5)
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout, OSError):
        return False


skip_if_no_dvwa = pytest.mark.skipif(
    not dvwa_available(),
    reason="DVWA not available at http://127.0.0.1:8080",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dvwa_session() -> requests.Session:
    """Create an authenticated DVWA session with security=low.

    Performs login via POST to /login.php and sets the security cookie
    to 'low' for all subsequent requests.
    """
    session = requests.Session()

    # Step 1: GET login page to obtain CSRF token
    login_page = session.get(f"{DVWA_BASE_URL}/login.php", timeout=10)
    assert login_page.status_code == 200, "Failed to reach DVWA login page"

    # Extract user_token from login form
    import re
    token_match = re.search(
        r"name=['\"]user_token['\"].*?value=['\"]([^'\"]+)['\"]",
        login_page.text,
    )
    user_token = token_match.group(1) if token_match else ""

    # Step 2: POST login credentials
    login_data = {
        "username": DVWA_USER,
        "password": DVWA_PASS,
        "Login": "Login",
        "user_token": user_token,
    }
    login_resp = session.post(
        f"{DVWA_BASE_URL}/login.php",
        data=login_data,
        allow_redirects=True,
        timeout=10,
    )
    # After successful login, DVWA redirects to index.php
    assert login_resp.status_code == 200, (
        f"DVWA login failed with status {login_resp.status_code}"
    )

    # Step 3: Set security level to low via cookie
    session.cookies.set("security", "low", domain="127.0.0.1", path="/")

    # Verify we are authenticated by accessing a protected page
    check = session.get(f"{DVWA_BASE_URL}/vulnerabilities/sqli/", timeout=10)
    assert check.status_code == 200, "Session not authenticated after login"

    return session


# ---------------------------------------------------------------------------
# Test Classes
# ---------------------------------------------------------------------------

@skip_if_no_dvwa
class TestDVWASQLi:
    """SQL Injection tests against DVWA /vulnerabilities/sqli/."""

    def test_sqli_route_detects_evidence(self, dvwa_session: requests.Session) -> None:
        """run_route('sqli') should detect SQL injection evidence on DVWA."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["sqli"]
        blackboard = WebStateBlackboard(target_url)

        # Seed blackboard with known parameter
        blackboard.record_param("id", location="query", suspected_route="sqli")

        result: RouteResult = run_route(
            route="sqli",
            target_url=target_url,
            blackboard=blackboard,
            param_name="id",
            session=dvwa_session,
            max_steps=10,
        )

        assert isinstance(result, RouteResult)
        assert result.route == "sqli"
        # The route should at least find evidence (score > 0)
        assert result.best_evidence_score > 0, (
            f"Expected evidence detection, got score={result.best_evidence_score}, "
            f"status={result.status}, stop_reason={result.stop_reason}"
        )

    def test_sqli_route_executes_steps(self, dvwa_session: requests.Session) -> None:
        """run_route('sqli') should execute at least 1 step."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["sqli"]
        blackboard = WebStateBlackboard(target_url)
        blackboard.record_param("id", location="query", suspected_route="sqli")

        result: RouteResult = run_route(
            route="sqli",
            target_url=target_url,
            blackboard=blackboard,
            param_name="id",
            session=dvwa_session,
            max_steps=10,
        )

        assert result.steps_executed >= 1, (
            f"Expected at least 1 step executed, got {result.steps_executed}"
        )


@skip_if_no_dvwa
class TestDVWACMDi:
    """Command Injection tests against DVWA /vulnerabilities/exec/."""

    def test_cmdi_route_detects_evidence(self, dvwa_session: requests.Session) -> None:
        """run_route('cmdi') should detect command injection evidence on DVWA."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["cmdi"]
        blackboard = WebStateBlackboard(target_url)

        # Seed blackboard with known parameter
        blackboard.record_param("ip", location="body", suspected_route="cmdi")

        result: RouteResult = run_route(
            route="cmdi",
            target_url=target_url,
            blackboard=blackboard,
            param_name="ip",
            session=dvwa_session,
            max_steps=10,
        )

        assert isinstance(result, RouteResult)
        assert result.route == "cmdi"
        assert result.best_evidence_score > 0, (
            f"Expected evidence detection, got score={result.best_evidence_score}, "
            f"status={result.status}, stop_reason={result.stop_reason}"
        )

    def test_cmdi_route_executes_steps(self, dvwa_session: requests.Session) -> None:
        """run_route('cmdi') should execute at least 1 step."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["cmdi"]
        blackboard = WebStateBlackboard(target_url)
        blackboard.record_param("ip", location="body", suspected_route="cmdi")

        result: RouteResult = run_route(
            route="cmdi",
            target_url=target_url,
            blackboard=blackboard,
            param_name="ip",
            session=dvwa_session,
            max_steps=10,
        )

        assert result.steps_executed >= 1, (
            f"Expected at least 1 step executed, got {result.steps_executed}"
        )


@skip_if_no_dvwa
class TestDVWALFI:
    """Local File Inclusion tests against DVWA /vulnerabilities/fi/."""

    def test_lfi_route_detects_evidence(self, dvwa_session: requests.Session) -> None:
        """run_route('lfi') should detect LFI evidence on DVWA."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["lfi"]
        blackboard = WebStateBlackboard(target_url)

        # Seed blackboard with known parameter
        blackboard.record_param("page", location="query", suspected_route="lfi")

        result: RouteResult = run_route(
            route="lfi",
            target_url=target_url,
            blackboard=blackboard,
            param_name="page",
            session=dvwa_session,
            max_steps=10,
        )

        assert isinstance(result, RouteResult)
        assert result.route == "lfi"
        assert result.best_evidence_score > 0, (
            f"Expected evidence detection, got score={result.best_evidence_score}, "
            f"status={result.status}, stop_reason={result.stop_reason}"
        )

    def test_lfi_route_executes_steps(self, dvwa_session: requests.Session) -> None:
        """run_route('lfi') should execute at least 1 step."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["lfi"]
        blackboard = WebStateBlackboard(target_url)
        blackboard.record_param("page", location="query", suspected_route="lfi")

        result: RouteResult = run_route(
            route="lfi",
            target_url=target_url,
            blackboard=blackboard,
            param_name="page",
            session=dvwa_session,
            max_steps=10,
        )

        assert result.steps_executed >= 1, (
            f"Expected at least 1 step executed, got {result.steps_executed}"
        )


@skip_if_no_dvwa
class TestDVWAXSS:
    """Reflected XSS tests against DVWA /vulnerabilities/xss_r/."""

    def test_xss_route_detects_evidence(self, dvwa_session: requests.Session) -> None:
        """run_route('xss') should detect XSS evidence on DVWA."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["xss"]
        blackboard = WebStateBlackboard(target_url)

        # Seed blackboard with known parameter
        blackboard.record_param("name", location="query", suspected_route="xss")

        result: RouteResult = run_route(
            route="xss",
            target_url=target_url,
            blackboard=blackboard,
            param_name="name",
            session=dvwa_session,
            max_steps=10,
        )

        assert isinstance(result, RouteResult)
        assert result.route == "xss"
        assert result.best_evidence_score > 0, (
            f"Expected evidence detection, got score={result.best_evidence_score}, "
            f"status={result.status}, stop_reason={result.stop_reason}"
        )

    def test_xss_route_executes_steps(self, dvwa_session: requests.Session) -> None:
        """run_route('xss') should execute at least 1 step."""
        target_url = DVWA_BASE_URL + DVWA_ROUTES["xss"]
        blackboard = WebStateBlackboard(target_url)
        blackboard.record_param("name", location="query", suspected_route="xss")

        result: RouteResult = run_route(
            route="xss",
            target_url=target_url,
            blackboard=blackboard,
            param_name="name",
            session=dvwa_session,
            max_steps=10,
        )

        assert result.steps_executed >= 1, (
            f"Expected at least 1 step executed, got {result.steps_executed}"
        )
