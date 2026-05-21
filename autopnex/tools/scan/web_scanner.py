"""Nikto-style light web scanner: checks common sensitive paths and security headers.

Includes SPA / catch-all false-positive mitigation via baseline fingerprinting.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request
from ...knowledge_base.vuln_patterns import VULN_PATTERNS

_NON_HTML_PATHS = frozenset({
    "/.git/config", "/.env", "/.DS_Store", "/.svn/entries",
    "/wp-config.php.bak", "/backup.zip", "/config.php.bak",
    "/phpinfo.php", "/server-status",
    "/actuator/env", "/actuator/health",
})


@register
class WebScannerTool(BaseTool):
    category = "scan"

    @property
    def name(self) -> str:
        return "web_scan"

    @property
    def description(self) -> str:
        return (
            "Light web scanner (Nikto-style): probes a curated list of sensitive files "
            "(/.env, /.git/config, /server-status, /actuator/*, backup archives, ...) "
            "and checks for missing security headers."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL to scan, e.g. http://target.tld"},
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        if not target:
            return ToolResult(False, self.name, "target required", error="missing_target")

        baseline = _probe_baseline(target)

        hits: List[Dict[str, Any]] = []
        for path in VULN_PATTERNS["sensitive_file"]["paths"]:
            url = target + path
            resp, err, _ = request("GET", url, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code in (200, 206) and _looks_meaningful(resp, baseline, path):
                hits.append(
                    {
                        "url": url,
                        "status": resp.status_code,
                        "size": len(resp.content or b""),
                        "content_type": resp.headers.get("content-type", ""),
                    }
                )

        # Security headers (on base URL)
        resp, err, _ = request("GET", target)
        missing_headers: List[str] = []
        if resp is not None:
            for h in VULN_PATTERNS["security_headers"]["required"]:
                if h not in {k.lower() for k in resp.headers.keys()}:
                    missing_headers.append(h)

        summary = (
            f"sensitive_files_hit={len(hits)}, missing_security_headers={len(missing_headers)}"
        )
        parsed_data: Dict[str, Any] = {
            "sensitive_files": hits,
            "missing_security_headers": missing_headers,
            "base_status": resp.status_code if resp else None,
        }
        if baseline:
            parsed_data["spa_catch_all_detected"] = True
        raw_lines = [f"[sensitive] {h['status']} {h['url']} ({h['size']}B)" for h in hits]
        raw_lines += [f"[missing-header] {h}" for h in missing_headers]
        return ToolResult(True, self.name, summary, parsed_data=parsed_data, raw_output="\n".join(raw_lines))


def _probe_baseline(target: str) -> Optional[Dict[str, Any]]:
    """Fetch a random nonexistent path to fingerprint SPA / catch-all routing.

    Returns a fingerprint dict when the server responds 200 to a garbage path
    (indicating a catch-all route), or None if it returns 404/other as expected.
    """
    canary = f"/__autopenx_canary_{uuid.uuid4().hex[:8]}"
    resp, _err, _ = request("GET", target + canary, allow_redirects=False)
    if resp is None or resp.status_code != 200:
        return None
    return {
        "body_hash": hashlib.sha256(resp.content).hexdigest(),
        "body_len": len(resp.content),
    }


def _looks_meaningful(resp, baseline: Optional[Dict[str, Any]], path: str) -> bool:
    """Decide whether a 200 response genuinely exposes a sensitive file."""
    body_bytes = resp.content or b""
    body = (resp.text or "")[:2048].lower()
    if not body:
        return False

    # 1) Generic soft-404 keyword check
    if any(kw in body for kw in ("not found", "404", "nothing here")) and len(body) < 400:
        return False

    # 2) SPA / catch-all: body identical to the nonexistent canary path
    if baseline:
        resp_hash = hashlib.sha256(body_bytes).hexdigest()
        if resp_hash == baseline["body_hash"]:
            return False
        # Body length within 5 % of baseline AND served as HTML → likely dynamic catch-all
        if baseline["body_len"] > 0 and path in _NON_HTML_PATHS:
            ratio = abs(len(body_bytes) - baseline["body_len"]) / baseline["body_len"]
            ct = resp.headers.get("content-type", "").lower()
            if ratio < 0.05 and "text/html" in ct:
                return False

    # 3) Non-HTML files served as a full HTML page are almost certainly catch-all FPs
    if path in _NON_HTML_PATHS:
        ct = resp.headers.get("content-type", "").lower()
        if "text/html" in ct and ("<!doctype" in body or "<html" in body):
            return False

    return True
