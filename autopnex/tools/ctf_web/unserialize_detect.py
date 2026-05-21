"""PHP Unserialize vulnerability detection tool for CTF challenges."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse, urlunparse

from ..base import BaseTool, ToolResult
from .._http import normalise_target, request


# PHP serialized payloads that trigger errors or reveal serialization handling
_UNSERIALIZE_PAYLOADS: List[Tuple[str, str]] = [
    # Malformed serialized string — triggers PHP warning/error
    ('O:1:"A":1:{s:1:"a";s:1:"b";}', "php_object"),
    # Serialized string with invalid class
    ('O:8:"stdClass":1:{s:4:"test";s:4:"data";}', "php_stdclass"),
    # Serialized array
    ('a:1:{i:0;s:4:"test";}', "php_array"),
    # Null byte injection in serialized string
    ('s:4:"test";', "php_string"),
    # Deeply nested to trigger recursion errors
    ('a:2:{i:0;a:2:{i:0;s:4:"test";i:1;s:4:"data";}i:1;s:4:"more";}', "php_nested"),
]

# Patterns that indicate PHP serialization is being processed
_VULN_INDICATORS: List[str] = [
    "unserialize()",
    "unserialize",
    "__wakeup",
    "__destruct",
    "__toString",
    "O:8:",
    "a:1:{",
    "s:4:",
    "PHP Fatal error",
    "PHP Warning",
    "PHP Notice",
    "Catchable fatal error",
    "Exception",
    "Stack trace",
    "serialize",
    "Serialization",
]

# Patterns that confirm PHP serialization format in response
_SERIALIZATION_PATTERNS = re.compile(
    r'(O:\d+:"[^"]+":|\ba:\d+:\{|s:\d+:"[^"]*";|i:\d+;|b:[01];|N;)',
    re.IGNORECASE,
)


class UnserializeDetectTool(BaseTool):
    category = "ctf_web"

    @property
    def name(self) -> str:
        return "unserialize_detect"

    @property
    def description(self) -> str:
        return (
            "Detect PHP unserialize() vulnerabilities. "
            "Sends crafted PHP serialized objects/arrays to detect if the application "
            "deserializes user input. Looks for PHP error messages, serialization patterns "
            "in responses, and other vulnerability indicators."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test for PHP unserialize vulnerability.",
                },
                "param": {
                    "type": "string",
                    "description": "Parameter name to inject serialized payloads into.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method to use. Default: POST.",
                },
            },
            "required": ["url", "param"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        param = kwargs.get("param", "")
        if not url or not param:
            return ToolResult(False, self.name, "url and param are required", error="missing_args")

        method = (kwargs.get("method") or "POST").upper()
        parsed_url = urlparse(url)
        base_url = urlunparse(parsed_url._replace(query=""))

        indicators_found: List[str] = []
        payloads_tested: List[str] = []
        errors: List[str] = []

        for payload, payload_type in _UNSERIALIZE_PAYLOADS:
            try:
                payloads_tested.append(payload)

                if method == "POST":
                    resp, err, _ = request("POST", base_url, data={param: payload}, timeout=10)
                else:
                    resp, err, _ = request(
                        "GET", base_url, params={param: payload}, timeout=10
                    )

                if err or resp is None:
                    errors.append(f"Request failed for payload type {payload_type!r}: {err}")
                    continue

                body = resp.text or ""
                body_lower = body.lower()

                # Check for PHP error/warning indicators
                for indicator in _VULN_INDICATORS:
                    if indicator.lower() in body_lower:
                        indicators_found.append(
                            f"payload_type={payload_type!r}: found indicator {indicator!r}"
                        )

                # Check for serialization format patterns in response
                serial_matches = _SERIALIZATION_PATTERNS.findall(body)
                if serial_matches:
                    indicators_found.append(
                        f"payload_type={payload_type!r}: serialization pattern in response: {serial_matches[:3]}"
                    )

                # Check HTTP status — 500 often means unserialize triggered an error
                if resp.status_code == 500:
                    indicators_found.append(
                        f"payload_type={payload_type!r}: HTTP 500 response (possible unserialize error)"
                    )

            except Exception as exc:  # noqa: BLE001
                errors.append(f"Error testing payload {payload_type!r}: {exc}")
                continue

        vulnerable = bool(indicators_found)
        summary = (
            f"{'PHP unserialize vulnerability indicators found' if vulnerable else 'No unserialize vulnerability detected'}. "
            f"Tested {len(payloads_tested)} payloads."
        )

        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            raw_output="\n".join(indicators_found + errors),
            parsed_data={
                "vulnerable": vulnerable,
                "param": param,
                "url": url,
                "method": method,
                "indicators": indicators_found,
                "payloads_tested": len(payloads_tested),
                "errors": errors,
                "severity": "HIGH" if vulnerable else "INFO",
            },
        )
