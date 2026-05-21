"""Very small SSRF probe: inject internal targets and look for tell-tale responses."""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request
from ...knowledge_base.vuln_patterns import VULN_PATTERNS


SSRF = VULN_PATTERNS["ssrf"]


@register
class SsrfDetectorTool(BaseTool):
    category = "vuln"
    requires_local_targets = True

    @property
    def name(self) -> str:
        return "ssrf_detect"

    @property
    def description(self) -> str:
        return (
            "Heuristic SSRF detector: replaces the target parameter with internal URLs "
            "(127.0.0.1, 169.254.169.254, localhost) and inspects response body / length "
            "for indicators of a server-side fetch."
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
        base_params.setdefault(parameter, "https://example.com")

        # Baseline with benign remote URL
        params_base = dict(base_params)
        params_base[parameter] = "https://example.com"
        base_resp = _send(method, parsed, params_base)
        base_len = len(base_resp.text or "") if base_resp else 0
        base_status = base_resp.status_code if base_resp else None

        hits: List[Dict[str, Any]] = []
        for payload in SSRF["payloads"]:
            params = dict(base_params)
            params[parameter] = payload
            resp = _send(method, parsed, params)
            if resp is None:
                continue
            body = (resp.text or "").lower()
            length_delta = abs(len(body) - base_len)
            indicator_hit = any(i in body for i in SSRF["indicators"])
            # Heuristic: significant length delta OR known indicator words OR metadata keywords.
            if indicator_hit or length_delta > max(100, 0.15 * base_len) or "ec2" in body or "iam" in body:
                hits.append(
                    {
                        "payload": payload,
                        "status": resp.status_code,
                        "length": len(body),
                        "delta": length_delta,
                        "indicator": indicator_hit,
                    }
                )

        vulnerable = bool(hits)
        summary = (
            f"{'LIKELY VULNERABLE' if vulnerable else 'not vulnerable'} "
            f"param={parameter} hits={len(hits)} base_status={base_status}"
        )
        parsed_data = {
            "vulnerable": vulnerable,
            "url": url,
            "parameter": parameter,
            "method": method,
            "hits": hits,
            "severity": SSRF["severity"] if vulnerable else "INFO",
        }
        return ToolResult(True, self.name, summary, parsed_data=parsed_data, raw_output=str(hits))


def _send(method: str, parsed_url, params: Dict[str, str]):
    if method == "GET":
        url = urlunparse(parsed_url._replace(query=urlencode(params, doseq=True)))
        resp, _err, _ = request("GET", url)
    else:
        url = urlunparse(parsed_url._replace(query=""))
        resp, _err, _ = request("POST", url, data=params)
    return resp
