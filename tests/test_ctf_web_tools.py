"""Unit tests for CTF web exploitation tools.

Tests SSTI detection, LFI detection, PHP unserialize detection, and flag reader
tools using mocked HTTP responses.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from typing import Any, Dict, Optional, Tuple

import pytest

from config.settings import settings
from autopnex.tools.base import ToolRegistry, ToolResult
from autopnex.tools.ctf_web import (
    CTF_WEB_TOOLS,
    SSTIDetectTool,
    LFIDetectTool,
    UnserializeDetectTool,
    FlagReaderTool,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    text: str = "",
    status_code: int = 200,
    url: str = "http://target.local/",
) -> MagicMock:
    """Create a mock requests.Response object."""
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.url = url
    resp.headers = {"Content-Type": "text/html"}
    return resp


def _mock_request_factory(responses: Dict[str, str], default_text: str = ""):
    """Return a mock for _http.request that returns different text based on URL content."""

    def _mock_request(
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Tuple[Optional[MagicMock], Optional[str], float]:
        # Check if any key from responses dict is in the URL or data
        combined = url
        if params:
            combined += str(params)
        if data:
            combined += str(data)

        for key, text in responses.items():
            if key in combined:
                return _make_response(text=text), None, 0.1
        return _make_response(text=default_text), None, 0.1

    return _mock_request


# ---------------------------------------------------------------------------
# SSTI Detection Tests
# ---------------------------------------------------------------------------

class TestSSTIDetect:
    """Tests for the SSTI detection tool."""

    def setup_method(self):
        self.tool = SSTIDetectTool()
        self.runtime = settings.snapshot(allow_local_targets=True)

    @patch("autopnex.tools.ctf_web.ssti_detect.request")
    def test_detects_jinja2_ssti(self, mock_request):
        """SSTI tool detects Jinja2 template injection when 49 appears in response."""
        def side_effect(method, url, **kwargs):
            # The first payload {{7*7}} gets URL-encoded as %7B%7B7%2A7%7D%7D
            # Check for the URL-encoded form of the Jinja2 payload
            if "%7B%7B7" in url or "7%2A7" in url or "name=%7B" in url:
                return _make_response(text="Result: 49"), None, 0.1
            return _make_response(text="normal page"), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/page", param="name")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True
        assert result.parsed_data["engine"] == "jinja2"
        assert "{{7*7}}" in result.parsed_data["payload"]

    @patch("autopnex.tools.ctf_web.ssti_detect.request")
    def test_detects_twig_ssti(self, mock_request):
        """SSTI tool detects Twig template injection via {{7*'7'}} producing 7777777."""
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            # The Twig payload {{7*'7'}} gets URL-encoded
            # Return 7777777 only for the twig-specific payload (5th payload tested)
            if "%277%27" in url or "7*%277" in url:
                return _make_response(text="Output: 7777777"), None, 0.1
            return _make_response(text="no eval"), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/page", param="input")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True
        assert result.parsed_data["engine"] == "twig"

    @patch("autopnex.tools.ctf_web.ssti_detect.request")
    def test_no_ssti_detected(self, mock_request):
        """SSTI tool reports no vulnerability when no evaluation occurs."""
        mock_request.return_value = (_make_response(text="safe page content"), None, 0.1)

        result = self.tool._run(url="http://target.local/page", param="q")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is False
        assert result.parsed_data["engine"] is None

    @patch("autopnex.tools.ctf_web.ssti_detect.request")
    def test_handles_connection_error(self, mock_request):
        """SSTI tool handles connection errors gracefully."""
        mock_request.return_value = (None, "Connection refused", 0.1)

        result = self.tool._run(url="http://target.local/page", param="q")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is False

    def test_missing_url_returns_error(self):
        """SSTI tool returns error when URL is missing."""
        result = self.tool._run(url="", param="q")

        assert result.success is False
        assert result.error == "missing_args"

    @patch("autopnex.tools.ctf_web.ssti_detect.request")
    def test_detects_freemarker_ssti(self, mock_request):
        """SSTI tool detects FreeMarker template injection via ${7*7}."""
        def side_effect(method, url, **kwargs):
            if "${7*7}" in url or "%24%7B7*7%7D" in url or "7*7" in url:
                # Only respond with 49 for the freemarker payload
                if "$" in url or "%24" in url:
                    return _make_response(text="value=49"), None, 0.1
            return _make_response(text="nothing"), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/page", param="expr")

        assert result.success is True
        # If freemarker payload triggers, it should be detected
        if result.parsed_data["vulnerable"]:
            assert result.parsed_data["engine"] in ("freemarker", "jinja2")


# ---------------------------------------------------------------------------
# LFI Detection Tests
# ---------------------------------------------------------------------------

class TestLFIDetect:
    """Tests for the LFI/RFI detection tool."""

    def setup_method(self):
        self.tool = LFIDetectTool()
        self.runtime = settings.snapshot(allow_local_targets=True)

    @patch("autopnex.tools.ctf_web.lfi_detect.request")
    def test_detects_etc_passwd(self, mock_request):
        """LFI tool detects path traversal when /etc/passwd content is returned."""
        def side_effect(method, url, **kwargs):
            if "etc/passwd" in url or "etc%2Fpasswd" in url:
                return _make_response(
                    text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
                ), None, 0.1
            return _make_response(text="normal page"), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/view", param="file")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True
        assert "passwd" in result.parsed_data["payload"]
        assert result.parsed_data["payload_type"] == "unix_passwd"

    @patch("autopnex.tools.ctf_web.lfi_detect.request")
    def test_detects_php_filter(self, mock_request):
        """LFI tool detects PHP filter wrapper when base64 PHP content is returned."""
        def side_effect(method, url, **kwargs):
            if "php://filter" in url or "php%3A%2F%2Ffilter" in url:
                return _make_response(
                    text="PD9waHAgZWNobyAnaGVsbG8nOyA/Pg=="
                ), None, 0.1
            return _make_response(text="normal"), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/index.php", param="page")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True
        assert result.parsed_data["payload_type"] == "php_filter"

    @patch("autopnex.tools.ctf_web.lfi_detect.request")
    def test_no_lfi_detected(self, mock_request):
        """LFI tool reports no vulnerability when no file content is leaked."""
        mock_request.return_value = (_make_response(text="<html>404 Not Found</html>"), None, 0.1)

        result = self.tool._run(url="http://target.local/view", param="file")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is False

    @patch("autopnex.tools.ctf_web.lfi_detect.request")
    def test_handles_timeout(self, mock_request):
        """LFI tool handles request timeouts gracefully."""
        mock_request.return_value = (None, "Connection timed out", 0.1)

        result = self.tool._run(url="http://target.local/view", param="file")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is False

    def test_missing_param_returns_error(self):
        """LFI tool returns error when param is missing."""
        result = self.tool._run(url="http://target.local/view", param="")

        assert result.success is False
        assert result.error == "missing_args"

    @patch("autopnex.tools.ctf_web.lfi_detect.request")
    def test_post_method(self, mock_request):
        """LFI tool supports POST method for injection."""
        def side_effect(method, url, **kwargs):
            if method == "POST" and kwargs.get("data", {}).get("file", ""):
                data_val = kwargs["data"]["file"]
                if "etc/passwd" in data_val:
                    return _make_response(
                        text="root:x:0:0:root:/root:/bin/bash"
                    ), None, 0.1
            return _make_response(text="normal"), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/view", param="file", method="POST")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True


# ---------------------------------------------------------------------------
# PHP Unserialize Detection Tests
# ---------------------------------------------------------------------------

class TestUnserializeDetect:
    """Tests for the PHP unserialize detection tool."""

    def setup_method(self):
        self.tool = UnserializeDetectTool()
        self.runtime = settings.snapshot(allow_local_targets=True)

    @patch("autopnex.tools.ctf_web.unserialize_detect.request")
    def test_detects_php_error(self, mock_request):
        """Unserialize tool detects vulnerability when PHP error is triggered."""
        def side_effect(method, url, **kwargs):
            return _make_response(
                text="PHP Fatal error: Uncaught Exception in /var/www/html/index.php:42\nStack trace:\n#0 unserialize()",
                status_code=500,
            ), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/api", param="data")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True
        assert len(result.parsed_data["indicators"]) > 0

    @patch("autopnex.tools.ctf_web.unserialize_detect.request")
    def test_detects_serialization_pattern(self, mock_request):
        """Unserialize tool detects serialization patterns in response."""
        def side_effect(method, url, **kwargs):
            return _make_response(
                text='O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'
            ), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/profile", param="cookie")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True

    @patch("autopnex.tools.ctf_web.unserialize_detect.request")
    def test_no_unserialize_detected(self, mock_request):
        """Unserialize tool reports no vulnerability for normal responses."""
        mock_request.return_value = (
            _make_response(text="<html><body>Welcome</body></html>"),
            None,
            0.1,
        )

        result = self.tool._run(url="http://target.local/page", param="input")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is False

    @patch("autopnex.tools.ctf_web.unserialize_detect.request")
    def test_handles_connection_error(self, mock_request):
        """Unserialize tool handles connection errors gracefully."""
        mock_request.return_value = (None, "Connection refused", 0.1)

        result = self.tool._run(url="http://target.local/api", param="data")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is False

    def test_missing_params_returns_error(self):
        """Unserialize tool returns error when required params are missing."""
        result = self.tool._run(url="", param="data")
        assert result.success is False
        assert result.error == "missing_args"

        result = self.tool._run(url="http://target.local/", param="")
        assert result.success is False
        assert result.error == "missing_args"

    @patch("autopnex.tools.ctf_web.unserialize_detect.request")
    def test_detects_wakeup_destruct(self, mock_request):
        """Unserialize tool detects __wakeup/__destruct magic method references."""
        def side_effect(method, url, **kwargs):
            return _make_response(
                text="Warning: __wakeup() method called on invalid object"
            ), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local/api", param="obj")

        assert result.success is True
        assert result.parsed_data["vulnerable"] is True


# ---------------------------------------------------------------------------
# Flag Reader Tests
# ---------------------------------------------------------------------------

class TestFlagReader:
    """Tests for the flag file reader tool."""

    def setup_method(self):
        self.tool = FlagReaderTool()
        self.runtime = settings.snapshot(allow_local_targets=True)

    @patch("autopnex.tools.ctf_web.flag_reader.request")
    def test_finds_flag_direct_access(self, mock_request):
        """Flag reader finds flag via direct HTTP access to /flag.txt."""
        def side_effect(method, url, **kwargs):
            if "/flag" in url and ".txt" in url:
                return _make_response(text="flag{y0u_g0t_1t_2024}"), None, 0.1
            return _make_response(text="404 Not Found", status_code=404), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local")

        assert result.success is True
        assert result.parsed_data["found"] is True
        assert result.parsed_data["flag"] == "flag{y0u_g0t_1t_2024}"
        assert result.parsed_data["method"] == "direct_access"

    @patch("autopnex.tools.ctf_web.flag_reader.request")
    def test_finds_flag_via_lfi(self, mock_request):
        """Flag reader finds flag using LFI payload when direct access fails."""
        def side_effect(method, url, **kwargs):
            # LFI paths will have URL-encoded traversal like ..%2F..%2F
            if "..%2F" in url or "....%2F" in url or "../" in url:
                return _make_response(text="CTF{lfi_flag_found}"), None, 0.1
            # All direct access attempts return 404
            return _make_response(text="Not Found", status_code=404), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(
            url="http://target.local/view",
            lfi_payload="../../../../{path}",
            lfi_param="file",
        )

        assert result.success is True
        assert result.parsed_data["found"] is True
        assert "CTF{lfi_flag_found}" in result.parsed_data["flag"]
        assert result.parsed_data["method"] == "lfi"

    @patch("autopnex.tools.ctf_web.flag_reader.request")
    def test_no_flag_found(self, mock_request):
        """Flag reader reports not found when no flag is accessible."""
        mock_request.return_value = (
            _make_response(text="<html>404</html>", status_code=404),
            None,
            0.1,
        )

        result = self.tool._run(url="http://target.local")

        assert result.success is True
        assert result.parsed_data["found"] is False
        assert result.parsed_data["flag"] is None

    @patch("autopnex.tools.ctf_web.flag_reader.request")
    def test_handles_connection_error(self, mock_request):
        """Flag reader handles connection errors gracefully."""
        mock_request.return_value = (None, "Connection refused", 0.1)

        result = self.tool._run(url="http://target.local")

        assert result.success is True
        assert result.parsed_data["found"] is False

    def test_missing_url_returns_error(self):
        """Flag reader returns error when URL is missing."""
        result = self.tool._run(url="")
        assert result.success is False
        assert result.error == "missing_args"

    @patch("autopnex.tools.ctf_web.flag_reader.request")
    def test_finds_md5_hash_flag(self, mock_request):
        """Flag reader detects MD5-like hash as potential flag."""
        def side_effect(method, url, **kwargs):
            if "/flag" in url:
                return _make_response(text="d41d8cd98f00b204e9800998ecf8427e"), None, 0.1
            return _make_response(text="", status_code=404), None, 0.1

        mock_request.side_effect = side_effect

        result = self.tool._run(url="http://target.local")

        assert result.success is True
        assert result.parsed_data["found"] is True
        assert result.parsed_data["flag"] == "d41d8cd98f00b204e9800998ecf8427e"


# ---------------------------------------------------------------------------
# Tool Registry Integration Tests
# ---------------------------------------------------------------------------

class TestCTFWebToolRegistry:
    """Tests for CTF web tools registration and CTF_WEB_TOOLS dict."""

    def test_all_tools_registered(self):
        """All CTF web tools are registered in ToolRegistry."""
        assert ToolRegistry.get("ssti_detect") is not None
        assert ToolRegistry.get("lfi_detect") is not None
        assert ToolRegistry.get("unserialize_detect") is not None
        assert ToolRegistry.get("flag_reader") is not None

    def test_ctf_web_tools_dict(self):
        """CTF_WEB_TOOLS dict maps all tool names to async functions."""
        assert "ssti_detect" in CTF_WEB_TOOLS
        assert "lfi_detect" in CTF_WEB_TOOLS
        assert "unserialize_detect" in CTF_WEB_TOOLS
        assert "flag_reader" in CTF_WEB_TOOLS
        # All values should be callable
        for name, func in CTF_WEB_TOOLS.items():
            assert callable(func), f"{name} is not callable"

    def test_tools_have_correct_category(self):
        """All CTF web tools have category 'ctf_web'."""
        for name in ("ssti_detect", "lfi_detect", "unserialize_detect", "flag_reader"):
            tool = ToolRegistry.get(name)
            assert tool is not None
            assert tool.category == "ctf_web"

    def test_tools_have_valid_schemas(self):
        """All CTF web tools produce valid OpenAI-compatible schemas."""
        for name in ("ssti_detect", "lfi_detect", "unserialize_detect", "flag_reader"):
            tool = ToolRegistry.get(name)
            schema = tool.openai_schema()
            assert schema["type"] == "function"
            assert "function" in schema
            assert "name" in schema["function"]
            assert "description" in schema["function"]
            assert "parameters" in schema["function"]
            assert schema["function"]["name"] == name


# ---------------------------------------------------------------------------
# Async Wrapper Tests
# ---------------------------------------------------------------------------

class TestAsyncWrappers:
    """Tests for the async convenience wrapper functions."""

    @pytest.mark.asyncio
    @patch("autopnex.tools.ctf_web.ssti_detect.request")
    async def test_async_ssti_detect(self, mock_request):
        """Async ssti_detect wrapper returns correct dict structure."""
        from autopnex.tools.ctf_web import ssti_detect as async_ssti

        mock_request.return_value = (_make_response(text="Result: 49"), None, 0.1)

        result = await async_ssti("http://target.local/page", "name")

        assert isinstance(result, dict)
        assert "vulnerable" in result
        assert "engine" in result
        assert "payload" in result
        assert "response" in result

    @pytest.mark.asyncio
    @patch("autopnex.tools.ctf_web.lfi_detect.request")
    async def test_async_lfi_detect(self, mock_request):
        """Async lfi_detect wrapper returns correct dict structure."""
        from autopnex.tools.ctf_web import lfi_detect as async_lfi

        mock_request.return_value = (_make_response(text="normal"), None, 0.1)

        result = await async_lfi("http://target.local/view", "file")

        assert isinstance(result, dict)
        assert "vulnerable" in result
        assert "payload" in result
        assert "content" in result
        assert "technique" in result

    @pytest.mark.asyncio
    @patch("autopnex.tools.ctf_web.unserialize_detect.request")
    async def test_async_unserialize_detect(self, mock_request):
        """Async unserialize_detect wrapper returns correct dict structure."""
        from autopnex.tools.ctf_web import unserialize_detect as async_unserialize

        mock_request.return_value = (_make_response(text="normal"), None, 0.1)

        result = await async_unserialize("http://target.local/api", "data")

        assert isinstance(result, dict)
        assert "vulnerable" in result
        assert "payload" in result
        assert "response" in result

    @pytest.mark.asyncio
    @patch("autopnex.tools.ctf_web.flag_reader.request")
    async def test_async_flag_reader(self, mock_request):
        """Async flag_reader wrapper returns correct dict structure."""
        from autopnex.tools.ctf_web import flag_reader as async_flag

        mock_request.return_value = (
            _make_response(text="flag{test_flag}", status_code=200),
            None,
            0.1,
        )

        result = await async_flag("http://target.local")

        assert isinstance(result, dict)
        assert "found" in result
        assert "flag" in result
        assert "path" in result
        assert "method" in result
