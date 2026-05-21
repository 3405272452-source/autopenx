"""gowitness batch web screenshot tool.

Runs locally if gowitness binary is found; otherwise falls back to Docker.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .docker_manager import DockerManager


@register
class GowitnessTool(BaseTool):
    category = "recon"

    @property
    def name(self) -> str:
        return "gowitness"

    @property
    def description(self) -> str:
        return (
            "Take batch web screenshots using gowitness. "
            "Runs locally if gowitness is installed; otherwise uses Docker. "
            "Generates a visual gallery of web pages for reconnaissance."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to screenshot.",
                },
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of URLs to screenshot instead of single target.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in milliseconds (default: 120000).",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        urls = kwargs.get("urls", [])
        timeout = kwargs.get("timeout", 120000)

        if not target and not urls:
            return ToolResult(False, self.name, "target or urls required", error="missing_args")

        # Determine local vs Docker execution
        local_path = DockerManager.find_binary("gowitness")

        if local_path:
            output_dir = os.path.join(tempfile.gettempdir(), "gowitness-output")
            os.makedirs(output_dir, exist_ok=True)

            if urls:
                url_file = os.path.join(tempfile.gettempdir(), "gowitness-urls.txt")
                with open(url_file, "w") as f:
                    f.write("\n".join(urls))
                command = f"gowitness file -f {url_file} -P {output_dir} --no-json 2>&1"
            else:
                command = f"gowitness single -u {target} -P {output_dir} 2>&1"

            result = DockerManager.exec_local(command, timeout)

            # Count screenshots locally
            screenshot_count = len([f for f in os.listdir(output_dir) if f.endswith(".png")]) if os.path.isdir(output_dir) else 0
        else:
            docker = DockerManager.get_instance()
            output_dir = "/tmp/gowitness-output"

            if urls:
                url_list = "\n".join(urls)
                docker.exec_command(f"echo '{url_list}' > /tmp/gowitness-urls.txt", 10000)
                command = f"gowitness file -f /tmp/gowitness-urls -P {output_dir} --no-json 2>&1 | tail -20"
            else:
                command = f"gowitness single -u {target} -P {output_dir} 2>&1"

            result = docker.exec_command(command, timeout)

            ls_result = docker.exec_command(f"ls -la {output_dir}/*.png 2>/dev/null | wc -l", 5000)
            screenshot_count = 0
            try:
                screenshot_count = int(ls_result.stdout.strip())
            except (ValueError, TypeError):
                pass

        success = screenshot_count > 0 or result.exit_code == 0
        summary = f"gowitness: {screenshot_count} screenshots taken for {target or 'URL list'}"

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "target": target,
                "screenshot_count": screenshot_count,
                "output_dir": output_dir,
                "exit_code": result.exit_code,
            },
            raw_output=result.stdout[:3000],
        )
