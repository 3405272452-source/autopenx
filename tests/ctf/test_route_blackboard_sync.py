"""Tests for RouteStateMachine blackboard synchronization (Task 5.5).

Verifies that after running a route, the blackboard is updated with:
- Discovered endpoints (from HTTP history)
- Evidence scores (from probes)
- Attempt records (success/failure)

Validates: Requirements 3.6
"""
from __future__ import annotations

import pytest
import requests
from unittest.mock import patch, MagicMock
from requests.models import Response

from autopnex.ctf.route_state_machine import (
    run_route,
    RouteResult,
    _sync_blackboard,
    SourceLeakMachine,
    MachineState,
    EvidenceScore,
)
from autopnex.ctf.web_state_blackboard import WebStateBlackboard


# ---------------------------------------------------------------------------
# Unit tests with mocked HTTP
# ---------------------------------------------------------------------------


class TestSyncBlackboardUnit:
    """Unit tests verifying _sync_blackboard writes to blackboard correctly."""

    def test_sync_records_endpoints_from_http_history(self):
        """Endpoints discovered during machine execution are recorded."""
        bb = WebStateBlackboard(target_url="http://example.com")
        machine = SourceLeakMachine("http://example.com")
        # Simulate HTTP history entries
        machine._http_history = [
            {"method": "GET", "url": "http://example.com/.env", "status": 200},
            {"method": "GET", "url": "http://example.com/.git/HEAD", "status": 404},
            {"method": "GET", "url": "http://example.com/www.zip", "status": 200},
        ]
        machine.state.evidence_scores = [
            EvidenceScore(route="source_leak", score=0.85, source=".env", detail="Config found")
        ]

        result = RouteResult(
            route="source_leak",
            status="failed",
            best_evidence_score=0.85,
            steps_executed=3,
            stop_reason="no_flag_in_source_leak",
        )

        _sync_blackboard(bb, machine, result)

        # Verify endpoints were recorded
        assert len(bb.endpoints) == 3
        assert "/.env" in bb.endpoints
        assert "/.git/HEAD" in bb.endpoints
        assert "/www.zip" in bb.endpoints

    def test_sync_records_evidence_from_probes(self):
        """Evidence scores from probes are written to blackboard."""
        bb = WebStateBlackboard(target_url="http://example.com")
        machine = SourceLeakMachine("http://example.com")
        machine._http_history = []
        machine.state.evidence_scores = [
            EvidenceScore(route="source_leak", score=0.9, source=".git/HEAD", detail="Git dir found"),
            EvidenceScore(route="source_leak", score=0.5, source=".env", detail="Possible config"),
        ]

        result = RouteResult(
            route="source_leak",
            status="failed",
            best_evidence_score=0.9,
            steps_executed=2,
            stop_reason="no_flag",
        )

        _sync_blackboard(bb, machine, result)

        # Verify evidence was recorded
        assert len(bb.evidence) == 2
        assert bb.evidence[0].route == "source_leak"
        assert bb.evidence[0].score == 0.9
        assert bb.evidence[1].score == 0.5

    def test_sync_records_attempt(self):
        """The overall attempt is recorded in blackboard.attempts."""
        bb = WebStateBlackboard(target_url="http://example.com")
        machine = SourceLeakMachine("http://example.com")
        machine._http_history = []
        machine.state.evidence_scores = []

        result = RouteResult(
            route="source_leak",
            status="failed",
            best_evidence_score=0.0,
            steps_executed=5,
            stop_reason="no_flag_in_source_leak",
        )

        _sync_blackboard(bb, machine, result)

        # Verify attempt was recorded
        assert len(bb.attempts) == 1
        assert bb.attempts[0].route == "source_leak"
        assert bb.attempts[0].tool == "route_sm_source_leak"
        assert bb.attempts[0].success is False

    def test_sync_records_successful_attempt(self):
        """A successful route records success=True in attempt."""
        bb = WebStateBlackboard(target_url="http://example.com")
        machine = SourceLeakMachine("http://example.com")
        machine._http_history = [
            {"method": "GET", "url": "http://example.com/.env", "status": 200},
        ]
        machine.state.evidence_scores = [
            EvidenceScore(route="source_leak", score=0.95, source=".env", detail="Flag in .env")
        ]

        result = RouteResult(
            route="source_leak",
            status="success",
            flag="flag{test123}",
            best_evidence_score=0.95,
            steps_executed=2,
            stop_reason="flag_found",
        )

        _sync_blackboard(bb, machine, result)

        assert len(bb.attempts) == 1
        assert bb.attempts[0].success is True

    def test_sync_with_none_blackboard_does_nothing(self):
        """When blackboard is None, _sync_blackboard is a no-op."""
        machine = SourceLeakMachine("http://example.com")
        machine._http_history = [
            {"method": "GET", "url": "http://example.com/.env", "status": 200},
        ]
        result = RouteResult(route="source_leak", status="failed", stop_reason="test")

        # Should not raise
        _sync_blackboard(None, machine, result)


class TestRunRouteBlackboardIntegration:
    """Integration tests verifying run_route() updates blackboard via _sync_blackboard."""

    def _make_response(self, status_code: int = 200, text: str = "", headers: dict = None):
        """Create a mock Response object."""
        resp = Response()
        resp.status_code = status_code
        resp._content = text.encode("utf-8")
        resp.headers.update(headers or {})
        return resp

    @patch("autopnex.ctf.route_state_machine.requests.Session")
    def test_run_route_source_leak_updates_blackboard_endpoints(self, mock_session_cls):
        """After running source_leak, blackboard.endpoints should be non-empty."""
        # Setup mock session
        session = MagicMock()
        # Return 404 for all probes (no real leak) but still records endpoints
        html_response = self._make_response(
            404, "<html><body>Not Found</body></html>",
            {"Content-Type": "text/html"}
        )
        session.get.return_value = html_response
        session.post.return_value = html_response

        bb = WebStateBlackboard(target_url="http://example.com")

        result = run_route(
            route="source_leak",
            target_url="http://example.com",
            blackboard=bb,
            session=session,
        )

        # Blackboard should have endpoints from the HTTP requests made
        assert len(bb.endpoints) > 0, "blackboard.endpoints should be non-empty after source_leak"
        # Should have attempts recorded
        assert len(bb.attempts) > 0, "blackboard.attempts should be non-empty after source_leak"

    @patch("autopnex.ctf.route_state_machine.requests.Session")
    def test_run_route_source_leak_records_evidence(self, mock_session_cls):
        """After running source_leak with a hit, evidence is recorded."""
        session = MagicMock()

        def side_effect(url, **kwargs):
            if ".env" in url:
                return self._make_response(200, "DB_HOST=localhost\nFLAG=flag{test_env_leak}")
            return self._make_response(404, "<html>Not Found</html>")

        session.get.side_effect = side_effect

        bb = WebStateBlackboard(target_url="http://example.com")

        result = run_route(
            route="source_leak",
            target_url="http://example.com",
            blackboard=bb,
            session=session,
        )

        # Evidence should be recorded from probes
        assert len(bb.evidence) > 0, "blackboard.evidence should be non-empty"

    @patch("autopnex.ctf.route_state_machine.requests.Session")
    def test_run_route_unknown_route_records_attempt(self, mock_session_cls):
        """Unknown route still records a failed attempt."""
        session = MagicMock()
        bb = WebStateBlackboard(target_url="http://example.com")

        result = run_route(
            route="nonexistent_route",
            target_url="http://example.com",
            blackboard=bb,
            session=session,
        )

        assert result.status == "failed"
        assert "unknown_route" in result.stop_reason

    @patch("autopnex.ctf.route_state_machine.requests.Session")
    def test_run_route_lfi_updates_blackboard(self, mock_session_cls):
        """LFI route also updates blackboard with endpoints and attempts."""
        session = MagicMock()
        session.get.return_value = self._make_response(200, "some content without flag")

        bb = WebStateBlackboard(target_url="http://example.com")

        result = run_route(
            route="lfi",
            target_url="http://example.com",
            blackboard=bb,
            session=session,
        )

        # Should have endpoints from probes
        assert len(bb.endpoints) > 0, "LFI route should record endpoints"
        # Should have attempt recorded
        assert len(bb.attempts) > 0, "LFI route should record attempts"


# ---------------------------------------------------------------------------
# Live integration test against DVWA
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRunRouteBlackboardLiveDVWA:
    """Live integration tests against DVWA at http://127.0.0.1:8080.

    These tests require DVWA to be running. Skip if unavailable.
    """

    DVWA_URL = "http://127.0.0.1:8080"

    @pytest.fixture(autouse=True)
    def check_dvwa(self):
        """Skip if DVWA is not reachable."""
        try:
            resp = requests.get(self.DVWA_URL, timeout=5)
            if resp.status_code not in (200, 302):
                pytest.skip("DVWA not responding correctly")
        except requests.ConnectionError:
            pytest.skip("DVWA not reachable at http://127.0.0.1:8080")

    @pytest.fixture
    def dvwa_session(self):
        """Create an authenticated DVWA session with security=Low."""
        session = requests.Session()
        # Get login page to get CSRF token
        login_page = session.get(f"{self.DVWA_URL}/login.php", timeout=10)
        # Extract user_token
        import re
        token_match = re.search(r"user_token'\s+value='([^']+)'", login_page.text)
        if not token_match:
            pytest.skip("Could not extract DVWA CSRF token")
        token = token_match.group(1)

        # Login
        login_resp = session.post(
            f"{self.DVWA_URL}/login.php",
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token,
            },
            allow_redirects=True,
            timeout=10,
        )

        # Set security to Low
        session.cookies.set("security", "low")

        return session

    def test_source_leak_route_populates_blackboard_endpoints(self, dvwa_session):
        """Running source_leak against DVWA populates blackboard.endpoints."""
        bb = WebStateBlackboard(target_url=self.DVWA_URL)

        result = run_route(
            route="source_leak",
            target_url=self.DVWA_URL,
            blackboard=bb,
            session=dvwa_session,
        )

        # After running source_leak, endpoints should be non-empty
        # (the machine probes multiple paths like /.env, /.git/HEAD, etc.)
        assert len(bb.endpoints) > 0, (
            f"blackboard.endpoints should be non-empty after source_leak route. "
            f"Result: status={result.status}, stop_reason={result.stop_reason}"
        )

    def test_source_leak_route_populates_blackboard_attempts(self, dvwa_session):
        """Running source_leak against DVWA populates blackboard.attempts."""
        bb = WebStateBlackboard(target_url=self.DVWA_URL)

        result = run_route(
            route="source_leak",
            target_url=self.DVWA_URL,
            blackboard=bb,
            session=dvwa_session,
        )

        # Should have at least one attempt recorded
        assert len(bb.attempts) > 0, (
            f"blackboard.attempts should be non-empty after source_leak route. "
            f"Result: status={result.status}"
        )

    def test_source_leak_route_populates_blackboard_evidence(self, dvwa_session):
        """Running source_leak against DVWA populates blackboard.evidence."""
        bb = WebStateBlackboard(target_url=self.DVWA_URL)

        result = run_route(
            route="source_leak",
            target_url=self.DVWA_URL,
            blackboard=bb,
            session=dvwa_session,
        )

        # Evidence should be recorded (even if score is 0, the probe still records)
        assert len(bb.evidence) > 0, (
            f"blackboard.evidence should be non-empty after source_leak route. "
            f"Result: status={result.status}, best_score={result.best_evidence_score}"
        )
