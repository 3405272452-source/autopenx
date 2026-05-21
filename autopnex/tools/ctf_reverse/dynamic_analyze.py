"""Dynamic analysis tool for CTF reverse engineering challenges.

Provides dynamic analysis of binaries using:
- ltrace: trace library calls
- strace: trace system calls

Graceful fallback when tools are unavailable.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def dynamic_analyze(binary_path: str, method: str = "ltrace") -> dict:
    """Perform dynamic analysis on a binary using ltrace or strace.

    Args:
        binary_path: Path to the binary to analyze.
        method: Analysis method - "ltrace" (library calls) or "strace" (syscalls).

    Returns:
        dict with keys: success, syscalls, library_calls, output.
    """
    result: Dict[str, Any] = {
        "success": False,
        "syscalls": [],
        "library_calls": [],
        "output": "",
    }

    if not binary_path:
        result["error"] = "binary_path is required"
        return result

    path = Path(binary_path)
    if not path.exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result

    # Validate method
    method = method.lower()
    if method not in ("ltrace", "strace"):
        result["error"] = f"Invalid method: {method}. Use 'ltrace' or 'strace'."
        return result

    # Check if the tool is available
    tool_bin = shutil.which(method)
    if not tool_bin:
        result["error"] = (
            f"{method} is not available on this system. "
            f"Install it with: sudo apt-get install {method}"
        )
        result["output"] = (
            f"Dynamic analysis tool '{method}' not found.\n"
            f"\nAlternative approaches:\n"
            f"1. Install {method}: sudo apt-get install {method}\n"
            f"2. Use GDB for manual debugging: gdb {binary_path}\n"
            f"3. Use strace/ltrace in a Docker container\n"
            f"4. Analyze statically with strings/objdump instead\n"
        )
        return result

    # Execute the analysis tool
    try:
        if method == "ltrace":
            cmd = [tool_bin, "-e", "*", "-s", "256", binary_path]
        else:  # strace
            cmd = [tool_bin, "-f", "-s", "256", binary_path]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
        )

        # ltrace/strace output goes to stderr
        output = proc.stderr or proc.stdout or ""
        result["output"] = output[:20000]  # Limit output size

        # Parse the output
        if method == "ltrace":
            result["library_calls"] = _parse_ltrace_output(output)
        else:
            result["syscalls"] = _parse_strace_output(output)

        result["success"] = True

    except subprocess.TimeoutExpired:
        result["error"] = f"{method} timed out after 30 seconds"
        result["output"] = "Process timed out - binary may be waiting for input or stuck in a loop."
    except PermissionError:
        result["error"] = f"Permission denied running {method}. May need elevated privileges."
    except (OSError, IOError) as exc:
        result["error"] = f"{method} execution error: {exc}"

    return result


# ---------------------------------------------------------------------------
# Output parsing helpers
# ---------------------------------------------------------------------------


def _parse_ltrace_output(output: str) -> List[str]:
    """Parse ltrace output to extract library calls."""
    calls: List[str] = []
    seen: set = set()

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # ltrace format: "function_name(args) = return_value"
        # or: "pid function_name(args) = return_value"
        # Skip +++ and --- lines
        if line.startswith("+++") or line.startswith("---"):
            continue

        # Extract the function call part
        if "(" in line:
            # Remove PID prefix if present
            parts = line.split(None, 1)
            if parts and parts[0].isdigit() and len(parts) > 1:
                line = parts[1]

            # Get function name
            func_name = line.split("(")[0].strip()
            if func_name and func_name not in seen:
                seen.add(func_name)
                calls.append(line[:200])  # Limit line length

    return calls


def _parse_strace_output(output: str) -> List[str]:
    """Parse strace output to extract system calls."""
    calls: List[str] = []
    seen_types: set = set()

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # strace format: "syscall_name(args) = return_value"
        # Skip +++ and --- lines
        if line.startswith("+++") or line.startswith("---"):
            continue

        # Extract syscall name
        if "(" in line:
            # Remove PID prefix if present
            parts = line.split(None, 1)
            if parts and parts[0].isdigit() and len(parts) > 1:
                line = parts[1]

            syscall_name = line.split("(")[0].strip()
            if syscall_name:
                # Keep unique syscall types but allow multiple instances
                call_key = f"{syscall_name}"
                if call_key not in seen_types or len(calls) < 200:
                    seen_types.add(call_key)
                    calls.append(line[:200])

    return calls


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------


@register
class DynamicAnalyzeTool(BaseTool):
    """Dynamic analysis of binaries using ltrace/strace."""

    category = "ctf_reverse"
    external_binary = "ltrace"

    @property
    def name(self) -> str:
        return "dynamic_analyze"

    @property
    def description(self) -> str:
        return (
            "Perform dynamic analysis on a binary using ltrace (library calls) "
            "or strace (system calls). Useful for understanding runtime behavior "
            "of reverse engineering challenges."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary to analyze.",
                },
                "method": {
                    "type": "string",
                    "description": "Analysis method: 'ltrace' or 'strace' (default: 'ltrace').",
                    "default": "ltrace",
                    "enum": ["ltrace", "strace"],
                },
            },
            "required": ["binary_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        binary_path = kwargs.get("binary_path", "")
        method = kwargs.get("method", "ltrace")

        if not binary_path:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="binary_path is required",
                error="missing_args",
            )

        if not Path(binary_path).exists():
            return ToolResult(
                success=False,
                tool=self.name,
                summary=f"Binary not found: {binary_path}",
                error="file_not_found",
            )

        exec_result = dynamic_analyze(binary_path, method)

        if exec_result["success"]:
            syscalls_count = len(exec_result["syscalls"])
            lib_calls_count = len(exec_result["library_calls"])
            summary = (
                f"Dynamic analysis ({method}): "
                f"{syscalls_count} syscalls, {lib_calls_count} library calls captured"
            )
            return ToolResult(
                success=True,
                tool=self.name,
                summary=summary,
                parsed_data={
                    "method": method,
                    "syscalls": exec_result["syscalls"][:50],
                    "library_calls": exec_result["library_calls"][:50],
                },
                raw_output=exec_result["output"][:2000],
            )
        else:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=exec_result.get("error", "Dynamic analysis failed"),
                error=exec_result.get("error", "unknown_error"),
                parsed_data={"output": exec_result.get("output", "")},
            )
