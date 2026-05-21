"""Reflected Cross-Site Scripting detector (lightweight)."""
from __future__ import annotations

import html
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request
from ...knowledge_base.vuln_patterns import VULN_PATTERNS


XSS = VULN_PATTERNS["xss_reflected"]


@register
class XssDetectorTool(BaseTool):
    category = "vuln"

    @property
    def name(self) -> str:
        return "xss_detect"

    @property
    def description(self) -> str:
        return (
            "Detect reflected XSS on a parameter by injecting marker-tagged payloads and "
            "checking that the payload is reflected unencoded in the HTTP response body."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "parameter": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST"]},
            },
            "required": ["url", "parameter"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        parameter = kwargs.get("parameter")
        if not url or not parameter:
            return ToolResult(False, self.name, "url and parameter required", error="missing_args")
        method = (kwargs.get("method") or "GET").upper()

        parsed = urlparse(url)
        base_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        base_params.setdefault(parameter, "test")

        hits: List[Dict[str, Any]] = []
        for payload in XSS["payloads"]:
            marker = f"autopnex{abs(hash(payload)) % 100000}"
            wrapped = payload.replace("alert(1)", f"alert('{marker}')") if "alert(1)" in payload else payload + marker
            params = dict(base_params)
            params[parameter] = wrapped
            if method == "GET":
                u = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
                resp, err, _ = request("GET", u)
            else:
                u = urlunparse(parsed._replace(query=""))
                resp, err, _ = request("POST", u, data=params)
            if resp is None:
                continue
            body = resp.text or ""
            if wrapped in body and html.escape(wrapped) not in body:
                hits.append({"payload": wrapped, "status": resp.status_code, "length": len(body)})

        vulnerable = bool(hits)
        summary = f"{'VULNERABLE' if vulnerable else 'not vulnerable'} param={parameter} hits={len(hits)}"
        parsed_data = {
            "vulnerable": vulnerable,
            "url": url,
            "parameter": parameter,
            "method": method,
            "reflections": hits,
            "severity": XSS["severity"] if vulnerable else "INFO",
        }
        return ToolResult(True, self.name, summary, parsed_data=parsed_data, raw_output=str(hits))
