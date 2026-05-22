"""Hydra brute-force password cracker.

Runs locally if hydra binary is found; otherwise falls back to Docker.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .docker_manager import DockerManager


@register
class HydraCrackTool(BaseTool):
    category = "exploit"
    requires_exploit_enabled = True
    required_capability = "exploit"

    @property
    def name(self) -> str:
        return "hydra_crack"

    @property
    def description(self) -> str:
        return (
            "Run Hydra brute-force password cracking. "
            "Runs locally if hydra is installed; otherwise uses Docker. "
            "Supports HTTP-Form, SSH, FTP, SMB, and 50+ protocols. "
            "Requires exploit authorization."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or URL.",
                },
                "service": {
                    "type": "string",
                    "description": "Service to attack (e.g. 'ssh', 'ftp', 'http-form-post', 'smb').",
                },
                "username": {
                    "type": "string",
                    "description": "Single username or path to username list file.",
                },
                "password_list": {
                    "type": "string",
                    "description": "Path to password list file inside container (e.g. '/usr/share/wordlists/rockyou.txt').",
                },
                "form_data": {
                    "type": "string",
                    "description": "For HTTP form: 'login=^USER^&pass=^PASS^' pattern.",
                },
                "form_url": {
                    "type": "string",
                    "description": "For HTTP form: the login endpoint path.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in milliseconds (default: 600000).",
                },
            },
            "required": ["target", "service", "username"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        service = kwargs.get("service", "ssh")
        username = kwargs.get("username", "")
        password_list = kwargs.get("password_list", "/usr/share/wordlists/rockyou.txt")
        form_data = kwargs.get("form_data", "")
        form_url = kwargs.get("form_url", "")
        timeout = kwargs.get("timeout", 600000)

        if not target or not username:
            return ToolResult(False, self.name, "target and username required", error="missing_args")

        # Build hydra command
        cmd_parts = ["hydra", "-l", username, "-P", password_list, "-t", "4", "-f", "-V"]

        if service.startswith("http-form"):
            if not form_url:
                return ToolResult(False, self.name, "form_url required for HTTP form attack", error="missing_args")
            cmd_parts.extend([target, service, form_url])
            if form_data:
                cmd_parts.append(form_data)
        else:
            cmd_parts.extend([target, service])

        command = " ".join(cmd_parts)

        # Local-first: try local hydra, fall back to Docker
        local_path = DockerManager.find_binary("hydra")
        if local_path:
            result = DockerManager.exec_local(command, timeout)
        else:
            docker = DockerManager.get_instance()
            result = docker.exec_command(command, timeout)

        # Parse hydra output for cracked credentials
        cracked: List[Dict[str, str]] = []
        for line in result.stdout.split("\n"):
            match = re.search(r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)", line)
            if match:
                cracked.append({
                    "port": match.group(1),
                    "service": match.group(2),
                    "host": match.group(3),
                    "username": match.group(4),
                    "password": match.group(5).strip(),
                })

        success = bool(cracked)
        summary = f"Hydra: {len(cracked)} credentials cracked on {target}"
        if not success:
            summary = f"Hydra: no credentials cracked on {target}"

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "target": target,
                "service": service,
                "cracked": cracked,
                "total": len(cracked),
                "exit_code": result.exit_code,
            },
            raw_output=result.stdout[:5000],
        )
