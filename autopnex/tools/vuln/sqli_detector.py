"""Reflected SQL injection detector using error / boolean / time-based signals."""
from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request
from ...knowledge_base.vuln_patterns import VULN_PATTERNS


SQLI = VULN_PATTERNS["sql_injection"]


def _build_url(url: str, params: Dict[str, str]) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(query=urlencode(params, doseq=True)))


@register
class SqliDetectorTool(BaseTool):
    category = "vuln"

    @property
    def name(self) -> str:
        return "sqli_detect"

    @property
    def description(self) -> str:
        return (
            "Detect SQL injection on a single URL + parameter using three signals: "
            "(1) database error messages, (2) boolean true/false response-length divergence, "
            "(3) time-based payload causing a ~5s delay."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL including the parameter baseline."},
                "parameter": {"type": "string", "description": "Parameter name to fuzz."},
                "method": {"type": "string", "enum": ["GET", "POST"], "description": "Default GET."},
                "baseline_value": {"type": "string", "description": "Optional baseline value, default '1'."},
            },
            "required": ["url", "parameter"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        parameter = kwargs.get("parameter")
        if not url or not parameter:
            return ToolResult(False, self.name, "url and parameter required", error="missing_args")
        method = (kwargs.get("method") or "GET").upper()
        baseline = kwargs.get("baseline_value") or "1"

        parsed = urlparse(url)
        base_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        base_params.setdefault(parameter, baseline)

        base_resp = _send(method, parsed, base_params, parameter, baseline)
        if base_resp is None:
            return ToolResult(False, self.name, "baseline request failed", error="baseline_fail")
        base_len = len(base_resp.text or "")
        evidence: List[str] = []
        confirmed_signals: List[str] = []
        payload_used = None

        # 1) Error-based
        for p in SQLI["error_payloads"]:
            resp = _send(method, parsed, base_params, parameter, baseline + p)
            if resp is None:
                continue
            body = (resp.text or "").lower()
            for indicator in SQLI["indicators"]:
                if indicator in body:
                    evidence.append(f"error-based via payload {p!r}: matched {indicator!r}")
                    confirmed_signals.append("error")
                    payload_used = baseline + p
                    break
            if "error" in confirmed_signals:
                break

        # 2) Boolean-based
        if "error" not in confirmed_signals:
            true_p = SQLI["boolean_true"][0]
            false_p = SQLI["boolean_false"][0]
            rt = _send(method, parsed, base_params, parameter, baseline + true_p)
            rf = _send(method, parsed, base_params, parameter, baseline + false_p)
            if rt is not None and rf is not None:
                lt, lf = len(rt.text or ""), len(rf.text or "")
                if abs(lt - base_len) < 40 and abs(lf - lt) > max(50, 0.1 * base_len):
                    evidence.append(
                        f"boolean-based: true-payload length={lt} (≈baseline {base_len}), "
                        f"false-payload length={lf} (Δ={abs(lf-lt)})"
                    )
                    confirmed_signals.append("boolean")
                    payload_used = baseline + true_p

        # 3) Time-based (try MySQL, then PostgreSQL, then MSSQL)
        if not confirmed_signals:
            time_payloads = [
                ("mysql", SQLI["time_payloads_mysql"][0]),
                ("pgsql", SQLI["time_payloads_pgsql"][0]),
                ("mssql", SQLI["time_payloads_mssql"][0]),
            ]
            for db_label, tp in time_payloads:
                start = time.perf_counter()
                rt = _send(method, parsed, base_params, parameter, baseline + tp, timeout_override=10)
                elapsed = time.perf_counter() - start
                if rt is not None and elapsed >= 4.5:
                    evidence.append(f"time-based ({db_label}): payload {tp!r} caused {elapsed:.2f}s delay")
                    confirmed_signals.append("time")
                    payload_used = baseline + tp
                    break

        vulnerable = bool(confirmed_signals)
        summary = (
            f"{'VULNERABLE' if vulnerable else 'not vulnerable'} "
            f"param={parameter} signals={confirmed_signals or 'none'}"
        )
        parsed_data = {
            "vulnerable": vulnerable,
            "url": url,
            "parameter": parameter,
            "method": method,
            "signals": confirmed_signals,
            "payload": payload_used,
            "evidence": evidence,
            "severity": SQLI["severity"] if vulnerable else "INFO",
        }
        return ToolResult(True, self.name, summary, parsed_data=parsed_data, raw_output="\n".join(evidence))


def _send(method: str, parsed_url, base_params: Dict[str, str], parameter: str, value: str, *, timeout_override=None):
    params = dict(base_params)
    params[parameter] = value
    if method == "GET":
        url = _build_url(urlunparse(parsed_url._replace(query="")), params)
        resp, _err, _ = request("GET", url, timeout=timeout_override)
    else:
        url = urlunparse(parsed_url._replace(query=""))
        resp, _err, _ = request("POST", url, data=params, timeout=timeout_override)
    return resp
