"""Nuclei template-based vulnerability scanner.

Runs locally if nuclei binary is found; otherwise falls back to Docker.
"""
from __future__ import annotations

import json
import shutil
from typing import Any, Dict

from ..base import BaseTool, ToolResult, register
from .docker_manager import DockerManager


@register
class NucleiScanTool(BaseTool):
    category = "vuln"

    @property
    def name(self) -> str:
        return "nuclei_scan"

    @property
    def description(self) -> str:
        return (
            "Run ProjectDiscovery Nuclei template-based vulnerability scanning. "
            "Runs locally if nuclei is installed; otherwise uses Docker. "
            "Covers CVEs, misconfigurations, exposed panels, default credentials."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or IP address.",
                },
                "templates": {
                    "type": "string",
                    "description": "Optional template path or tags (e.g. 'cves,misconfigs'). Default: all templates.",
                },
                "severity_filter": {
                    "type": "string",
                    "description": "Severity filter (e.g. 'critical,high,medium'). Default: all severities.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in milliseconds (default: 600000 = 10 minutes).",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        templates = kwargs.get("templates", "")
        severity_filter = kwargs.get("severity_filter", "")
        timeout = kwargs.get("timeout", 600000)

        if not target:
            return ToolResult(False, self.name, "target is required", error="missing_args")

        # Build nuclei command
        cmd_parts = ["nuclei", "-u", target, "-jsonl", "-silent"]
        if templates:
            if "/" in templates or "\\" in templates:
                cmd_parts.extend(["-t", templates])
            else:
                cmd_parts.extend(["-tags", templates])
        if severity_filter:
            cmd_parts.extend(["-severity", severity_filter])

        command = " ".join(cmd_parts)

        # Local-first: try local nuclei, fall back to Docker
        local_path = DockerManager.find_binary("nuclei")
        if local_path:
            result = DockerManager.exec_local(command, timeout)
        else:
            docker = DockerManager.get_instance()
            result = docker.exec_command(command, timeout)

        # Parse JSONL output
        findings = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                findings.append({
                    "template_id": entry.get("template-id", ""),
                    "name": entry.get("info", {}).get("name", ""),
                    "severity": entry.get("info", {}).get("severity", "info"),
                    "matched_at": entry.get("matched-at", ""),
                    "type": entry.get("type", ""),
                    "description": entry.get("info", {}).get("description", "")[:200],
                    "reference": entry.get("info", {}).get("reference", []),
                })
            except json.JSONDecodeError:
                continue

        summary = f"Nuclei: {len(findings)} findings on {target}"
        if severity_filter:
            summary += f" (severity={severity_filter})"

        return ToolResult(
            success=result.exit_code == 0 or bool(findings),
            tool=self.name,
            summary=summary,
            parsed_data={
                "target": target,
                "findings": findings,
                "total": len(findings),
                "exit_code": result.exit_code,
            },
            raw_output=result.stdout[:5000],
        )
