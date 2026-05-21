"""Unit tests for ReconModule.fetch_robots() and fetch_sitemap()."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from autopnex.ctf.recon_module import ReconModule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_recon(base_url: str = "http://target:8080") -> ReconModule:
    """Create a ReconModule with a mock session."""
    session = MagicMock(spec=requests.Session)
    return ReconModule(session=session, base_url=base_url)


def _mock_response(status_code: int = 200, text: str = "") -> MagicMock:
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(
            f"{status_code} Error"
        )
    return resp


# ---------------------------------------------------------------------------
# fetch_robots() tests
# ---------------------------------------------------------------------------


class TestFetchRobots:
    """Tests for ReconModule.fetch_robots()."""

    def test_parses_disallow_paths(self):
        recon = _make_recon()
        robots_txt = (
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /secret/\n"
            "Allow: /public\n"
        )
        recon._session.get.return_value = _mock_response(200, robots_txt)

        result = recon.fetch_robots()

        assert "/admin" in result
        assert "/secret/" in result
        assert "/public" in result

    def test_skips_comments_and_empty_lines(self):
        recon = _make_recon()
        robots_txt = (
            "# This is a comment\n"
            "\n"
            "User-agent: *\n"
            "Disallow: /hidden\n"
            "# Another comment\n"
        )
        recon._session.get.return_value = _mock_response(200, robots_txt)

        result = recon.fetch_robots()

        assert result == ["/hidden"]

    def test_returns_empty_on_404(self):
        recon = _make_recon()
        recon._session.get.return_value = _mock_response(404, "Not Found")

        result = recon.fetch_robots()

        assert result == []

    def test_returns_empty_on_connection_error(self):
        recon = _make_recon()
        recon._session.get.side_effect = requests.ConnectionError("refused")

        result = recon.fetch_robots()

        assert result == []

    def test_returns_empty_on_timeout(self):
        recon = _make_recon()
        recon._session.get.side_effect = requests.Timeout("timed out")

        result = recon.fetch_robots()

        assert result == []

    def test_ignores_empty_disallow(self):
        """Disallow with no path (empty value) should be skipped."""
        recon = _make_recon()
        robots_txt = "User-agent: *\nDisallow: \nDisallow: /real\n"
        recon._session.get.return_value = _mock_response(200, robots_txt)

        result = recon.fetch_robots()

        assert result == ["/real"]

    def test_case_insensitive_directives(self):
        recon = _make_recon()
        robots_txt = "DISALLOW: /upper\nallow: /lower\nDisAllow: /mixed\n"
        recon._session.get.return_value = _mock_response(200, robots_txt)

        result = recon.fetch_robots()

        assert "/upper" in result
        assert "/lower" in result
        assert "/mixed" in result

    def test_uses_correct_url(self):
        recon = _make_recon("http://example.com:9090")
        recon._session.get.return_value = _mock_response(200, "")

        recon.fetch_robots()

        recon._session.get.assert_called_once_with(
            "http://example.com:9090/robots.txt", timeout=10
        )


# ---------------------------------------------------------------------------
# fetch_sitemap() tests
# ---------------------------------------------------------------------------


class TestFetchSitemap:
    """Tests for ReconModule.fetch_sitemap()."""

    def test_parses_loc_tags(self):
        recon = _make_recon()
        sitemap_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            "  <url><loc>http://target:8080/page1</loc></url>\n"
            "  <url><loc>http://target:8080/page2</loc></url>\n"
            "</urlset>"
        )
        recon._session.get.return_value = _mock_response(200, sitemap_xml)

        result = recon.fetch_sitemap()

        assert "http://target:8080/page1" in result
        assert "http://target:8080/page2" in result

    def test_returns_empty_on_404(self):
        recon = _make_recon()
        recon._session.get.return_value = _mock_response(404, "Not Found")

        result = recon.fetch_sitemap()

        assert result == []

    def test_returns_empty_on_connection_error(self):
        recon = _make_recon()
        recon._session.get.side_effect = requests.ConnectionError("refused")

        result = recon.fetch_sitemap()

        assert result == []

    def test_returns_empty_on_timeout(self):
        recon = _make_recon()
        recon._session.get.side_effect = requests.Timeout("timed out")

        result = recon.fetch_sitemap()

        assert result == []

    def test_handles_whitespace_in_loc(self):
        recon = _make_recon()
        sitemap_xml = "<urlset><url><loc>  http://target/path  </loc></url></urlset>"
        recon._session.get.return_value = _mock_response(200, sitemap_xml)

        result = recon.fetch_sitemap()

        assert result == ["http://target/path"]

    def test_case_insensitive_loc_tags(self):
        recon = _make_recon()
        sitemap_xml = "<urlset><url><LOC>http://target/upper</LOC></url></urlset>"
        recon._session.get.return_value = _mock_response(200, sitemap_xml)

        result = recon.fetch_sitemap()

        assert result == ["http://target/upper"]

    def test_uses_correct_url(self):
        recon = _make_recon("http://example.com:9090")
        recon._session.get.return_value = _mock_response(200, "")

        recon.fetch_sitemap()

        recon._session.get.assert_called_once_with(
            "http://example.com:9090/sitemap.xml", timeout=10
        )

    def test_empty_sitemap_returns_empty_list(self):
        recon = _make_recon()
        recon._session.get.return_value = _mock_response(200, "<urlset></urlset>")

        result = recon.fetch_sitemap()

        assert result == []


# ===========================================================================
# Property-Based Tests (round 7, task 3.6)
# ===========================================================================
"""Hypothesis-based properties verifying universal correctness of ReconModule.

Properties covered:

- **Property 4: HTML 链接/表单/JS 提取完整性**
  *For any* valid HTML document containing hyperlinks, form actions, and
  script src attributes, the extraction functions SHALL return all such
  elements without omission.

  **Validates: Requirements 3.2**

- **Property 5: JS API 端点模式检测**
  *For any* JavaScript content containing API endpoint string literals
  (matching ``/api/`` or fetch/axios URL patterns), the Recon_Module SHALL
  detect and return all such patterns.

  **Validates: Requirements 3.3**

- **Property 6: 侦察容错性**
  *For any* sequence of HTTP responses including 404 errors and connection
  failures, the Recon_Module SHALL complete scanning and return results for
  all successfully fetched targets without raising an exception.

  **Validates: Requirements 3.5**
"""
from typing import Any, Dict, List

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from autopnex.ctf.recon_module import AttackSurface


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# URL/path safe characters — no HTML metacharacters, no whitespace, no quotes.
# Keeps generated URLs valid inside the ``href="..."`` / ``src="..."`` /
# ``action="..."`` attribute regex used by the module.
_URL_PATH_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "/-_.~"
)

# A path-like URL that starts with `/` and contains url-safe characters.
# Excludes `#` and `javascript:` to avoid the extractor's intentional drops.
url_path_strategy = st.text(
    alphabet=_URL_PATH_ALPHABET,
    min_size=2,
    max_size=40,
).map(lambda s: "/" + s.lstrip("/"))

# An API endpoint path under /api/ (used by Property 5). At least one segment
# after `/api/` so it always appears as a non-trivial endpoint.
api_endpoint_strategy = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-_",
    min_size=1,
    max_size=30,
).map(lambda s: "/api/" + s.lstrip("/"))

# Form input name (alphanumeric, no quotes/whitespace).
input_name_strategy = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    min_size=1,
    max_size=20,
)

# HTTP method values accepted by extract_forms.
method_strategy = st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"])


# ---------------------------------------------------------------------------
# Property 4: HTML 链接/表单/JS 提取完整性
# ---------------------------------------------------------------------------


class TestHtmlExtractionCompleteness:
    """**Validates: Requirements 3.2**

    For any HTML document containing hyperlinks, form actions, and script
    src attributes, ``extract_links``, ``extract_forms``, and
    ``extract_js_urls`` SHALL return every embedded element.
    """

    @given(hrefs=st.lists(url_path_strategy, min_size=1, max_size=15, unique=True))
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_extract_links_returns_every_anchor(self, hrefs: List[str]) -> None:
        """All ``<a href="...">`` URLs are returned by ``extract_links``."""
        recon = _make_recon()
        anchors = "\n".join(f'<a href="{h}">link</a>' for h in hrefs)
        html = f"<html><body>{anchors}</body></html>"

        result = recon.extract_links(html)

        assert set(hrefs).issubset(set(result)), (
            f"Missing hrefs: {set(hrefs) - set(result)}"
        )

    @given(srcs=st.lists(url_path_strategy, min_size=1, max_size=15, unique=True))
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_extract_js_urls_returns_every_script_src(
        self, srcs: List[str]
    ) -> None:
        """All ``<script src="...">`` URLs are returned by ``extract_js_urls``."""
        recon = _make_recon()
        scripts = "\n".join(f'<script src="{s}"></script>' for s in srcs)
        html = f"<html><head>{scripts}</head><body></body></html>"

        result = recon.extract_js_urls(html)

        assert set(srcs).issubset(set(result)), (
            f"Missing js urls: {set(srcs) - set(result)}"
        )

    @given(
        forms_spec=st.lists(
            st.tuples(
                url_path_strategy,
                method_strategy,
                st.lists(input_name_strategy, min_size=0, max_size=4, unique=True),
            ),
            min_size=1,
            max_size=8,
        )
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_extract_forms_returns_every_form(
        self,
        forms_spec: List[tuple],
    ) -> None:
        """All ``<form>`` blocks are returned with action, method, and inputs."""
        recon = _make_recon()
        form_html_parts: List[str] = []
        for action, method, inputs in forms_spec:
            inputs_html = "".join(
                f'<input name="{name}" type="text">' for name in inputs
            )
            form_html_parts.append(
                f'<form action="{action}" method="{method}">{inputs_html}</form>'
            )
        html = f"<html><body>{''.join(form_html_parts)}</body></html>"

        result = recon.extract_forms(html)

        # One returned form per input form (no omission).
        assert len(result) == len(forms_spec), (
            f"Expected {len(forms_spec)} forms, got {len(result)}"
        )

        # Each input form must appear in output with matching action+method
        # (method is normalized to upper-case by the extractor).
        result_pairs = [(f["action"], f["method"]) for f in result]
        expected_pairs = [(a, m.upper()) for a, m, _ in forms_spec]
        assert result_pairs == expected_pairs

        # Every declared input name must appear in the corresponding form.
        for declared, returned in zip(forms_spec, result):
            _, _, declared_inputs = declared
            returned_names = {inp["name"] for inp in returned["inputs"]}
            assert set(declared_inputs).issubset(returned_names), (
                f"Missing inputs: {set(declared_inputs) - returned_names}"
            )


# ---------------------------------------------------------------------------
# Property 5: JS API 端点模式检测
# ---------------------------------------------------------------------------


class TestJsApiEndpointDetection:
    """**Validates: Requirements 3.3**

    For any JavaScript content containing API endpoint string literals,
    ``scan_js_for_apis`` SHALL detect and return all such patterns.
    """

    @given(endpoints=st.lists(api_endpoint_strategy, min_size=1, max_size=15, unique=True))
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_api_string_literals_are_detected(
        self, endpoints: List[str]
    ) -> None:
        """Plain ``"/api/..."`` string literals embedded in JS are returned."""
        recon = _make_recon()
        body_lines = [f'const URL_{i} = "{ep}";' for i, ep in enumerate(endpoints)]
        js = "\n".join(body_lines)

        result = recon.scan_js_for_apis(js)

        assert set(endpoints).issubset(set(result)), (
            f"Missing endpoints: {set(endpoints) - set(result)}"
        )

    @given(endpoints=st.lists(api_endpoint_strategy, min_size=1, max_size=10, unique=True))
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_fetch_call_urls_are_detected(self, endpoints: List[str]) -> None:
        """Endpoints inside ``fetch("...")`` calls are returned."""
        recon = _make_recon()
        js = "\n".join(f'fetch("{ep}");' for ep in endpoints)

        result = recon.scan_js_for_apis(js)

        assert set(endpoints).issubset(set(result)), (
            f"Missing endpoints: {set(endpoints) - set(result)}"
        )

    @given(
        items=st.lists(
            st.tuples(
                # Restrict to methods that won't ambiguously consume generated
                # paths (the regex matches a fixed set of HTTP verb names).
                st.sampled_from(["get", "post", "put", "patch", "head"]),
                api_endpoint_strategy,
            ),
            min_size=1,
            max_size=10,
        )
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_axios_call_urls_are_detected(
        self, items: List[tuple]
    ) -> None:
        """Endpoints inside ``axios.<method>("...")`` calls are returned."""
        recon = _make_recon()
        js = "\n".join(f'axios.{method}("{ep}");' for method, ep in items)

        result = recon.scan_js_for_apis(js)

        endpoints = {ep for _, ep in items}
        assert endpoints.issubset(set(result)), (
            f"Missing endpoints: {endpoints - set(result)}"
        )


# ---------------------------------------------------------------------------
# Property 6: 侦察容错性
# ---------------------------------------------------------------------------


# Outcome model for a single mocked HTTP fetch.
# - ("ok", body) → 200 response with `body` as text
# - ("not_found", _) → 404 response (raise_for_status skipped by module)
# - ("connection_error", _) → raise requests.ConnectionError
# - ("timeout", _) → raise requests.Timeout
fetch_outcome_strategy = st.one_of(
    st.tuples(st.just("ok"), st.text(alphabet="abcdef ", max_size=20)),
    st.tuples(st.just("not_found"), st.just("")),
    st.tuples(st.just("connection_error"), st.just("")),
    st.tuples(st.just("timeout"), st.just("")),
)


class TestReconFaultTolerance:
    """**Validates: Requirements 3.5**

    For any sequence of HTTP responses including 404 errors and connection
    failures, ``ReconModule.scan()`` SHALL complete without raising and
    return an ``AttackSurface``.
    """

    @given(
        robots_outcome=fetch_outcome_strategy,
        sitemap_outcome=fetch_outcome_strategy,
        main_outcome=fetch_outcome_strategy,
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_scan_completes_for_any_response_mix(
        self,
        robots_outcome: tuple,
        sitemap_outcome: tuple,
        main_outcome: tuple,
    ) -> None:
        """``scan()`` always returns an AttackSurface even when fetches fail.

        Routes the three primary endpoints (``/robots.txt``, ``/sitemap.xml``,
        and the base URL) to independent randomly-generated outcomes —
        including connection errors and timeouts — and asserts the scan
        completes normally.
        """
        recon = _make_recon("http://target:8080")

        outcomes_by_url: Dict[str, tuple] = {
            "http://target:8080/robots.txt": robots_outcome,
            "http://target:8080/sitemap.xml": sitemap_outcome,
            "http://target:8080": main_outcome,
        }

        def fake_get(url: str, *args: Any, **kwargs: Any) -> Any:
            kind, body = outcomes_by_url.get(url, ("not_found", ""))
            if kind == "ok":
                return _mock_response(200, body)
            if kind == "not_found":
                return _mock_response(404, "")
            if kind == "connection_error":
                raise requests.ConnectionError("refused")
            if kind == "timeout":
                raise requests.Timeout("timed out")
            # Any unexpected URL also gets a 404 response.
            return _mock_response(404, "")

        recon._session.get.side_effect = fake_get

        # Must not raise, regardless of the outcome combination.
        surface = recon.scan()

        assert isinstance(surface, AttackSurface)
        assert isinstance(surface.paths, list)
        assert isinstance(surface.js_urls, list)
        assert isinstance(surface.api_endpoints, list)
        assert isinstance(surface.forms, list)
        assert isinstance(surface.robots_paths, list)
        assert isinstance(surface.sitemap_urls, list)

    @given(
        error=st.sampled_from(
            [
                requests.ConnectionError("refused"),
                requests.Timeout("timed out"),
                requests.HTTPError("500 Internal Server Error"),
                requests.RequestException("generic"),
                OSError("socket gone"),
            ]
        )
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
    )
    def test_scan_swallows_all_documented_errors(self, error: Exception) -> None:
        """``scan()`` never propagates documented network errors."""
        recon = _make_recon()
        recon._session.get.side_effect = error

        surface = recon.scan()
        assert isinstance(surface, AttackSurface)
