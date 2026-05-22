"""Generic Docker command executor — run any command in the Shannon container."""
from __future__ import annotations

from typing import Any, Dict

from ..base import BaseTool, ToolResult, register
from .docker_manager import DockerManager


@register
class DockerExecTool(BaseTool):
    category = "docker"
    external_binary = "docker"

    @property
    def name(self) -> str:
        return "docker_exec"

    @property
    def description(self) -> str:
        return (
            "Execute any shell command inside the Shannon Docker container. "
            "The container includes 600+ Kali Linux tools: nmap, sqlmap, nikto, "
            "gobuster, hydra, nuclei, ffuf, httpx, hashcat, john, chromium, "
            "playwright, python3, and more."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute inside the container.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in milliseconds (default: 300000 = 5 minutes).",
                },
            },
            "required": ["command"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        command = kwargs.get("command", "")
        timeout = kwargs.get("timeout", 300000)

        if not command:
            return ToolResult(False, self.name, "command is required", error="missing_args")

        docker = DockerManager.get_instance()
        result = docker.exec_command(command, timeout)

        summary = f"exit={result.exit_code} duration={result.duration_ms}ms"
        if result.exit_code != 0:
            summary = f"FAILED {summary}"

        return ToolResult(
            success=result.exit_code == 0,
            tool=self.name,
            summary=summary,
            raw_output=result.stdout[:5000],
            parsed_data={
                "exit_code": result.exit_code,
                "stdout": result.stdout[:3000],
                "stderr": result.stderr[:1000],
                "duration_ms": result.duration_ms,
            },
            error=result.stderr[:500] if result.exit_code != 0 else None,
        )
