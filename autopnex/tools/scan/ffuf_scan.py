"""Controlled ffuf wrapper for high-throughput content discovery."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from .._http import normalise_target
from ..base import BaseTool, ToolResult, register


WORDLIST = Path(__file__).resolve().parents[2] / "knowledge_base" / "wordlists" / "common_paths.txt"


@register
class FfufScanTool(BaseTool):
    category = "scan"
    external_binary = "ffuf"
    required_capability = "active_scan"

    @property
    def name(self) -> str:
        return "ffuf_scan"

    @property
    def description(self) -> str:
        return (
            "Run a controlled ffuf directory/content discovery pass using a small bundled wordlist. "
            "Only available when active-scan approval is present."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL to fuzz."},
                "timeout": {"type": "integer", "description": "ffuf timeout in seconds (default 10)."},
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        if not target:
            return ToolResult(False, self.name, "target is required", error="missing_target")
        cmd = [
            "ffuf",
            "-u",
            f"{target}/FUZZ",
            "-w",
            str(WORDLIST),
            "-json",
            "-maxtime",
            str(int(kwargs.get("timeout") or 10)),
            "-fc",
            "404",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        combined = "\n".join(part for part in [proc.stdout, proc.stderr] if part).strip()
        if not combined:
            return ToolResult(False, self.name, "ffuf produced no output", error=f"ffuf_exit_{proc.returncode}")

        hits = _parse_ffuf_lines(combined)
        summary = f"ffuf discovered {len(hits)} candidate paths on {target}"
        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            raw_output=combined[:4000],
            parsed_data={"hits": hits, "scanner": "ffuf", "target": target},
        )


def _parse_ffuf_lines(output: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = data.get("url") or ""
        if not url:
            continue
        hits.append(
            {
                "url": url,
                "status": data.get("status"),
                "words": data.get("words"),
                "length": data.get("length"),
            }
        )
    return hits
