"""Time-based command injection detector."""
from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request
from ...knowledge_base.vuln_patterns import VULN_PATTERNS


CMDI = VULN_PATTERNS["command_injection"]


@register
class CmdiDetectorTool(BaseTool):
    category = "vuln"

    @property
    def name(self) -> str:
        return "cmdi_detect"

    @property
    def description(self) -> str:
        return (
            "Detect OS command injection on a parameter using 5-second sleep payloads "
            "and simple response-time delta analysis."
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

        # Baseline
        t0 = time.perf_counter()
        _send(method, parsed, base_params)
        baseline_elapsed = time.perf_counter() - t0

        hits: List[Dict[str, Any]] = []
        for payload in CMDI["payloads"]:
            params = dict(base_params)
            params[parameter] = base_params[parameter] + payload
            t_start = time.perf_counter()
            resp = _send(method, parsed, params, timeout_override=12)
            elapsed = time.perf_counter() - t_start
            if resp is None:
                continue
            # Confirm by time delta >= 4s over baseline
            if elapsed - baseline_elapsed >= 4.0:
                hits.append(
                    {
                        "payload": payload,
                        "elapsed": round(elapsed, 2),
                        "baseline": round(baseline_elapsed, 2),
                    }
                )
                break  # stop at first positive to be polite

        vulnerable = bool(hits)
        summary = (
            f"{'VULNERABLE' if vulnerable else 'not vulnerable'} "
            f"param={parameter} baseline={baseline_elapsed:.2f}s hits={len(hits)}"
        )
        parsed_data = {
            "vulnerable": vulnerable,
            "url": url,
            "parameter": parameter,
            "method": method,
            "hits": hits,
            "severity": CMDI["severity"] if vulnerable else "INFO",
        }
        return ToolResult(True, self.name, summary, parsed_data=parsed_data, raw_output=str(hits))


def _send(method: str, parsed_url, params: Dict[str, str], *, timeout_override=None):
    if method == "GET":
        url = urlunparse(parsed_url._replace(query=urlencode(params, doseq=True)))
        resp, _err, _ = request("GET", url, timeout=timeout_override)
    else:
        url = urlunparse(parsed_url._replace(query=""))
        resp, _err, _ = request("POST", url, data=params, timeout=timeout_override)
    return resp
