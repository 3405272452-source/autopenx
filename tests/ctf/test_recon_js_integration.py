"""Tests for ReconAgent JS Analyzer integration (task 9.3).

Verifies:
  - ReconAgent._analyze_js_content() extracts API endpoints and writes to blackboard
  - Source map detection records evidence to blackboard
  - Secrets extraction records evidence to blackboard
  - JS files discovered via <script src="..."> are automatically analyzed
  - _is_js_response() correctly identifies JS content types
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock, PropertyMock
import pytest
import requests

from autopnex.ctf.multi_agent import ReconAgent
from autopnex.ctf.web_state_blackboard import WebStateBlackboard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def blackboard():
    """Create a fresh blackboard for testing."""
    return WebStateBlackboard(target_url="http://localhost:9000")


@pytest.fixture
def recon_agent(blackboard):
    """Create a ReconAgent instance."""
    return ReconAgent(blackboard, "http://localhost:9000")


# ---------------------------------------------------------------------------
# _is_js_response tests
# ---------------------------------------------------------------------------

class TestIsJsResponse:
    """Tests for _is_js_response detection."""

    def test_application_javascript_content_type(self, recon_agent):
        assert recon_agent._is_js_response(
            "http://localhost/app.js", "application/javascript"
        ) is True

    def test_text_javascript_content_type(self, recon_agent):
        assert recon_agent._is_js_response(
            "http://localhost/app.js", "text/javascript"
        ) is True

    def test_application_x_javascript_content_type(self, recon_agent):
        assert recon_agent._is_js_response(
            "http://localhost/app.js", "application/x-javascript; charset=utf-8"
        ) is True

    def test_js_url_extension_fallback(self, recon_agent):
        """URL ending in .js should be detected even without JS content type."""
        assert recon_agent._is_js_response(
            "http://localhost/static/bundle.js", "text/plain"
        ) is True

    def test_non_js_content(self, recon_agent):
        assert recon_agent._is_js_response(
            "http://localhost/index.html", "text/html"
        ) is False

    def test_js_url_with_query_params(self, recon_agent):
        """URL with .js before query params should be detected."""
        assert recon_agent._is_js_response(
            "http://localhost/app.js?v=123", "text/plain"
        ) is True


# ---------------------------------------------------------------------------
# _analyze_js_content tests
# ---------------------------------------------------------------------------

class TestAnalyzeJsContent:
    """Tests for _analyze_js_content integration with blackboard."""

    def test_extracts_api_endpoints_to_blackboard(self, recon_agent, blackboard):
        """API endpoints found in JS should be recorded to blackboard.endpoints."""
        js_content = '''
        const API_BASE = "/api/v1";
        fetch("/api/users/list");
        axios.get("/api/admin/config");
        '''
        result = recon_agent._analyze_js_content(
            "http://localhost:9000/static/app.js", js_content
        )

        # Verify endpoints were extracted
        assert len(result["api_endpoints"]) >= 3

        # Verify they were written to blackboard
        endpoint_paths = list(blackboard.endpoints.keys())
        assert any("/api/users/list" in p for p in endpoint_paths)
        assert any("/api/admin/config" in p for p in endpoint_paths)

    def test_source_map_recorded_to_blackboard(self, recon_agent, blackboard):
        """Source map URL should be recorded as evidence and endpoint."""
        js_content = '''
        var x = 1;
        //# sourceMappingURL=app.js.map
        '''
        result = recon_agent._analyze_js_content(
            "http://localhost:9000/static/app.js", js_content
        )

        # Verify source map was detected
        assert result["source_map"] == "app.js.map"

        # Verify evidence was added for source_leak route
        source_leak_evidence = [
            e for e in blackboard.evidence
            if e.route == "source_leak" and "source map" in e.observation.lower()
        ]
        assert len(source_leak_evidence) >= 1
        assert source_leak_evidence[0].score == 0.7

        # Verify source map URL was recorded as endpoint
        endpoint_paths = list(blackboard.endpoints.keys())
        assert any("app.js.map" in p for p in endpoint_paths)

    def test_secrets_recorded_as_evidence(self, recon_agent, blackboard):
        """Secrets found in JS should be recorded as high-score evidence."""
        js_content = '''
        const config = {
            api_key: "sk_live_ABCDEFGHIJKLMNOP1234",
            jwt_secret: "my_super_secret_key_123"
        };
        '''
        result = recon_agent._analyze_js_content(
            "http://localhost:9000/static/config.js", js_content
        )

        # Verify secrets were extracted
        assert len(result["secrets"]) >= 1

        # Verify evidence was added with high score
        secret_evidence = [
            e for e in blackboard.evidence
            if e.source == "js_analyzer" and "Secret" in e.observation
        ]
        assert len(secret_evidence) >= 1
        assert all(e.score == 0.85 for e in secret_evidence)

    def test_frontend_routes_recorded_as_endpoints(self, recon_agent, blackboard):
        """Frontend routes starting with / should be recorded as endpoints."""
        js_content = '''
        const routes = [
            { path: "/dashboard", component: Dashboard },
            { path: "/admin/settings", component: Settings },
            { path: "/login", component: Login },
        ];
        '''
        result = recon_agent._analyze_js_content(
            "http://localhost:9000/static/router.js", js_content
        )

        # Verify routes were extracted
        assert len(result["frontend_routes"]) >= 2

        # Verify they were recorded as endpoints
        endpoint_paths = list(blackboard.endpoints.keys())
        assert any("/dashboard" in p for p in endpoint_paths)
        assert any("/admin/settings" in p for p in endpoint_paths)

    def test_no_findings_does_not_error(self, recon_agent, blackboard):
        """JS content with no interesting patterns should not cause errors."""
        js_content = "var x = 1 + 2; console.log(x);"
        result = recon_agent._analyze_js_content(
            "http://localhost:9000/static/simple.js", js_content
        )

        assert result["api_endpoints"] == []
        assert result["source_map"] is None
        assert result["secrets"] == []
        assert result["frontend_routes"] == []

    def test_discovered_from_field_set_correctly(self, recon_agent, blackboard):
        """Endpoints from JS analysis should have correct discovered_from."""
        js_content = 'fetch("/api/health");'
        recon_agent._analyze_js_content(
            "http://localhost:9000/static/app.js", js_content
        )

        # Find the recorded endpoint
        for path, ep in blackboard.endpoints.items():
            if "health" in path:
                assert "js_analysis" in ep.discovered_from
                break
        else:
            pytest.fail("Expected endpoint /api/health not found in blackboard")


# ---------------------------------------------------------------------------
# _discover_and_analyze_js_files tests
# ---------------------------------------------------------------------------

class TestDiscoverAndAnalyzeJsFiles:
    """Tests for automatic JS file discovery from HTML."""

    def test_discovers_script_src_tags(self, recon_agent, blackboard):
        """Script tags with src should trigger JS analysis."""
        html = '''
        <html>
        <head>
            <script src="/static/app.js"></script>
            <script src="/static/vendor.js"></script>
        </head>
        <body>Hello</body>
        </html>
        '''

        js_content = 'fetch("/api/secret/endpoint");'

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = js_content
        mock_resp.headers = {"Content-Type": "application/javascript"}

        with patch.object(recon_agent.session, "get", return_value=mock_resp):
            recon_agent._discover_and_analyze_js_files(html)

        # Verify endpoints from JS were recorded
        endpoint_paths = list(blackboard.endpoints.keys())
        assert any("/api/secret/endpoint" in p for p in endpoint_paths)

    def test_skips_external_cdn_scripts(self, recon_agent, blackboard):
        """External CDN scripts should not be fetched."""
        html = '''
        <html>
        <script src="https://cdn.example.com/jquery.min.js"></script>
        <script src="/local/app.js"></script>
        </html>
        '''

        js_content = 'fetch("/api/local");'
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = js_content
        mock_resp.headers = {"Content-Type": "application/javascript"}

        call_urls = []

        def mock_get(url, **kwargs):
            call_urls.append(url)
            return mock_resp

        with patch.object(recon_agent.session, "get", side_effect=mock_get):
            recon_agent._discover_and_analyze_js_files(html)

        # Should only fetch local script, not CDN
        assert not any("cdn.example.com" in u for u in call_urls)
        assert any("/local/app.js" in u for u in call_urls)

    def test_handles_fetch_failure_gracefully(self, recon_agent, blackboard):
        """Network errors when fetching JS files should not crash."""
        html = '<script src="/static/broken.js"></script>'

        with patch.object(
            recon_agent.session, "get",
            side_effect=requests.RequestException("Connection refused")
        ):
            # Should not raise
            recon_agent._discover_and_analyze_js_files(html)

        # Blackboard should still be functional
        assert blackboard.endpoints is not None


# ---------------------------------------------------------------------------
# Integration with _scan_common_paths
# ---------------------------------------------------------------------------

class TestScanCommonPathsJsIntegration:
    """Tests that _scan_common_paths triggers JS analysis for JS responses."""

    def test_js_response_triggers_analysis(self, recon_agent, blackboard):
        """When a scanned path returns JS content, it should be analyzed."""
        js_content = '''
        fetch("/api/hidden/admin");
        //# sourceMappingURL=bundle.js.map
        '''

        def mock_get(url, **kwargs):
            resp = MagicMock()
            if "/api/" in url:
                resp.status_code = 200
                resp.text = js_content
                resp.content = js_content.encode()
                resp.headers = {"Content-Type": "application/javascript"}
            else:
                resp.status_code = 200
                resp.text = "<html><body>Hello</body></html>"
                resp.content = resp.text.encode()
                resp.headers = {"Content-Type": "text/html"}
            return resp

        with patch.object(recon_agent.session, "get", side_effect=mock_get):
            results = recon_agent._scan_common_paths()

        # The /api/ path should have triggered JS analysis
        api_findings = [f for f in results["findings"] if f.get("path") == "/api/"]
        assert len(api_findings) == 1
        assert "js_analysis" in api_findings[0]
