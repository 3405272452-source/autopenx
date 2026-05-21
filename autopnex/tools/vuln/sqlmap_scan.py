"""Controlled sqlmap adapter exposed through BaseTool."""
from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List

from .._http import normalise_target
from ..base import BaseTool, ToolResult, register


@register
class SqlmapScanTool(BaseTool):
    category = "vuln"
    external_binary = "sqlmap"
    required_capability = "active_scan"

    @property
    def name(self) -> str:
        return "sqlmap_scan"

    @property
    def description(self) -> str:
        return (
            "Run a controlled sqlmap probe for one URL and parameter. "
            "Only available when external tools are enabled and sqlmap is installed."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL."},
                "parameter": {"type": "string", "description": "Parameter name to test."},
                "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method."},
                "baseline_value": {
                    "type": "string",
                    "description": "Optional baseline parameter value used for POST data generation.",
                },
            },
            "required": ["url", "parameter"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        url = normalise_target(kwargs.get("url", ""))
        parameter = (kwargs.get("parameter") or "").strip()
        if not url or not parameter:
            return ToolResult(False, self.name, "url and parameter required", error="missing_args")

        method = (kwargs.get("method") or "GET").upper()
        baseline_value = str(kwargs.get("baseline_value") or "1")
        availability = self.availability()
        binary = availability["binary_path"] or self.external_binary

        cmd: List[str] = [
            str(binary),
            "--batch",
            "--smart",
            "--level=2",
            "--risk=2",
            "--random-agent",
            "--disable-coloring",
            "-u",
            url,
            "-p",
            parameter,
        ]
        if method == "POST":
            cmd.extend(["--data", f"{parameter}={baseline_value}"])

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        combined = "\n".join(part for part in [proc.stdout, proc.stderr] if part).strip()
        if not combined:
            return ToolResult(
                False,
                self.name,
                "sqlmap produced no output",
                error=f"sqlmap_exit_{proc.returncode}",
            )

        lower = combined.lower()
        not_injectable = (
            "do not appear to be injectable" in lower
            or "might not be injectable" in lower
            or "all tested parameters do not appear" in lower
        )
        has_positive = any(
            token in lower
            for token in [
                "is vulnerable",
                "appears to be injectable",
                "sql injection vulnerability",
            ]
        )
        vulnerable = has_positive and not not_injectable
        dbms_match = re.search(r"back-end dbms:\s*(.+)", combined, flags=re.IGNORECASE)
        dbms = dbms_match.group(1).strip() if dbms_match else ""
        evidence = _interesting_lines(combined)
        summary = (
            f"{'VULNERABLE' if vulnerable else 'not vulnerable'} param={parameter}"
            + (f" dbms={dbms}" if dbms else "")
        )
        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            raw_output=combined[:4000],
            parsed_data={
                "vulnerable": vulnerable,
                "url": url,
                "parameter": parameter,
                "method": method,
                "signals": ["sqlmap"] if vulnerable else [],
                "evidence": evidence,
                "payload": None,
                "dbms": dbms,
                "severity": "HIGH" if vulnerable else "INFO",
            },
        )


def _interesting_lines(output: str) -> List[str]:
    lines = []
    for line in output.splitlines():
        lowered = line.lower()
        if any(
            token in lowered
            for token in [
                "injectable",
                "back-end dbms",
                "parameter",
                "heuristic",
                "payload",
                "testing",
            ]
        ):
            lines.append(line.strip())
    return lines[:20]
