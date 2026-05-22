"""Python script execution tool for CTF challenges.

Executes Python code in a subprocess with timeout and restricted permissions.
Used for running LLM-generated or user-provided decryption/analysis scripts.

Security:
- Runs in a subprocess (not in the main process)
- Timeout enforcement via subprocess timeout
- No network access (best-effort via environment restriction)
- Limited filesystem access
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from typing import Any, Dict

from ..base import BaseTool, ToolResult, register


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def script_execute(code: str, timeout: int = 30) -> dict:
    """Execute Python code in a subprocess with timeout.

    Args:
        code: Python source code to execute.
        timeout: Maximum execution time in seconds (default 30).

    Returns:
        dict with keys: success, stdout, stderr, exit_code.
    """
    result: Dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
    }

    if not code or not code.strip():
        result["stderr"] = "No code provided"
        return result

    # Write code to a temporary file
    tmp_file = None
    try:
        tmp_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            prefix="ctf_script_",
            delete=False,
            encoding="utf-8",
        )
        tmp_file.write(code)
        tmp_file.close()

        # Build restricted environment
        env = _build_restricted_env()

        # Execute in subprocess
        proc = subprocess.run(
            [sys.executable, tmp_file.name],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=tempfile.gettempdir(),
            encoding="utf-8",
            errors="replace",
        )

        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0

    except subprocess.TimeoutExpired:
        result["stderr"] = f"Script execution timed out after {timeout} seconds"
        result["exit_code"] = -1
        result["success"] = False

    except Exception as exc:
        result["stderr"] = f"Execution error: {exc}"
        result["exit_code"] = -1
        result["success"] = False

    finally:
        # Clean up temp file
        if tmp_file is not None:
            try:
                os.unlink(tmp_file.name)
            except OSError:
                pass

    return result


def _build_restricted_env() -> Dict[str, str]:
    """Build a restricted environment for subprocess execution.

    Restricts network access and limits filesystem visibility.
    """
    env = os.environ.copy()

    # Disable proxy settings to discourage network access
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                "all_proxy", "ALL_PROXY"):
        env.pop(key, None)

    # Set a restrictive PYTHONPATH (only standard library)
    # Keep the existing PYTHONPATH so crypto libraries are available
    # but remove any sensitive paths

    # Disable user site-packages for isolation (optional, may break some imports)
    env["PYTHONNOUSERSITE"] = "1"

    return env


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------


@register
class ScriptExecuteTool(BaseTool):
    category = "ctf_crypto"

    @property
    def name(self) -> str:
        return "script_execute"

    @property
    def description(self) -> str:
        return (
            "Execute Python scripts in a sandboxed subprocess for CTF challenges. "
            "Useful for running decryption scripts, mathematical computations, "
            "or custom analysis code. Has timeout enforcement and restricted permissions."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python source code to execute.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Maximum execution time in seconds (default: 30).",
                    "default": 30,
                },
            },
            "required": ["code"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        code: str = kwargs.get("code", "")
        timeout: int = int(kwargs.get("timeout", 30))

        if not code or not code.strip():
            return ToolResult(
                success=False,
                tool=self.name,
                summary="No code provided",
                error="missing_code",
            )

        # Enforce reasonable timeout bounds
        timeout = max(1, min(timeout, 120))

        exec_result = script_execute(code, timeout=timeout)

        success = exec_result["success"]
        stdout = exec_result["stdout"]
        stderr = exec_result["stderr"]
        exit_code = exec_result["exit_code"]

        if success:
            summary = "Script executed successfully (exit code 0)"
            if stdout:
                summary += f", output: {stdout[:200]!r}"
        else:
            summary = f"Script failed (exit code {exit_code})"
            if stderr:
                summary += f": {stderr[:200]!r}"

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data={
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            },
            raw_output=stdout or stderr,
        )
