"""SSTI (Server-Side Template Injection) detection tool for CTF challenges."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult
from .._http import normalise_target, request


# Payloads and their expected result (7*7=49) with engine hints
_SSTI_PAYLOADS: List[Tuple[str, str]] = [
    ("{{7*7}}", "jinja2"),       # Jinja2 / Twig
    ("${7*7}", "freemarker"),    # FreeMarker / EL
    ("#{7*7}", "thymeleaf"),     # Thymeleaf / Ruby ERB
    ("<%= 7*7 %>", "erb"),       # Ruby ERB / EJS
    ("{{7*'7'}}", "twig"),       # Twig (produces 7777777)
]

_CONFIRM_VALUE = "49"
_TWIG_CONFIRM = "7777777"


def _build_url(base: str, params: Dict[str, str]) -> str:
    p = urlparse(base)
    return urlunparse(p._replace(query=urlencode(params, doseq=True)))


class SSTIDetectTool(BaseTool):
    category = "ctf_web"

    @property
    def name(self) -> str:
        return "ssti_detect"

    @property
    def description(self) -> str:
        return (
            "Detect Server-Side Template Injection (SSTI) vulnerabilities. "
            "Tests common template engine payloads (Jinja2, Twig, FreeMarker, ERB) "
            "and confirms injection by checking if 7*7=49 is evaluated in the response."
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
                    "description": "Query/form parameter name to inject into. If empty, appends payload to URL.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method to use. Default: GET.",
                },
            },
            "required": ["url"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        if not url:
            return ToolResult(False, self.name, "url is required", error="missing_args")

        param = kwargs.get("param", "")
        method = (kwargs.get("method") or "GET").upper()

        parsed_url = urlparse(url)
        base_params = dict(parse_qsl(parsed_url.query, keep_blank_values=True))

        findings: List[str] = []

        for payload, engine_hint in _SSTI_PAYLOADS:
            try:
                if param:
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
                else:
                    # Append payload directly to URL path/query
                    test_url = url + payload
                    resp, err, _ = request(method, test_url, timeout=10)

                if err or resp is None:
                    continue

                body = resp.text or ""

                # Check for numeric evaluation (7*7=49)
                if _CONFIRM_VALUE in body:
                    # Distinguish Twig from Jinja2 by trying the Twig-specific payload
                    confirmed_engine = engine_hint
                    if payload == "{{7*7}}" and _TWIG_CONFIRM not in body:
                        confirmed_engine = "jinja2"

                    findings.append(
                        f"SSTI confirmed: engine={confirmed_engine}, payload={payload!r}"
                    )
                    return ToolResult(
                        success=True,
                        tool=self.name,
                        summary=f"SSTI detected! Engine: {confirmed_engine}, Payload: {payload!r}",
                        raw_output=body[:500],
                        parsed_data={
                            "vulnerable": True,
                            "engine": confirmed_engine,
                            "payload": payload,
                            "param": param,
                            "url": url,
                            "method": method,
                            "evidence": f"Response contained '{_CONFIRM_VALUE}' after injecting {payload!r}",
                        },
                    )

                # Twig-specific check
                if payload == "{{7*'7'}}" and _TWIG_CONFIRM in body:
                    findings.append(f"SSTI confirmed: engine=twig, payload={payload!r}")
                    return ToolResult(
                        success=True,
                        tool=self.name,
                        summary=f"SSTI detected! Engine: twig, Payload: {payload!r}",
                        raw_output=body[:500],
                        parsed_data={
                            "vulnerable": True,
                            "engine": "twig",
                            "payload": payload,
                            "param": param,
                            "url": url,
                            "method": method,
                            "evidence": f"Response contained '{_TWIG_CONFIRM}' after injecting {payload!r}",
                        },
                    )

            except Exception as exc:  # noqa: BLE001
                findings.append(f"Error testing payload {payload!r}: {exc}")
                continue

        return ToolResult(
            success=True,
            tool=self.name,
            summary="No SSTI vulnerability detected.",
            raw_output="\n".join(findings),
            parsed_data={
                "vulnerable": False,
                "engine": None,
                "payload": None,
                "param": param,
                "url": url,
                "method": method,
                "evidence": "No template evaluation detected in responses.",
            },
        )
