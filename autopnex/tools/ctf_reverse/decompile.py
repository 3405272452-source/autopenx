"""Decompile tool for CTF reverse engineering challenges.

Provides decompilation/disassembly of binary files using:
1. Ghidra headless (analyzeHeadless) if available
2. objdump as fallback for disassembly
3. Manual analysis instructions if neither is available

Security:
- Uses subprocess with timeout enforcement
- No arbitrary code execution
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def decompile(binary_path: str, function: str = "main") -> dict:
    """Decompile or disassemble a binary file.

    Attempts Ghidra headless first, falls back to objdump, then provides
    manual analysis instructions.

    Args:
        binary_path: Path to the binary file to decompile.
        function: Target function name to decompile (default: "main").

    Returns:
        dict with keys: success, decompiled_code, functions, tool_used.
    """
    result: Dict[str, Any] = {
        "success": False,
        "decompiled_code": "",
        "functions": [],
        "tool_used": "none",
    }

    if not binary_path:
        result["error"] = "binary_path is required"
        return result

    path = Path(binary_path)
    if not path.exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result

    # Try Ghidra headless first
    ghidra_result = _try_ghidra(binary_path, function)
    if ghidra_result["success"]:
        return ghidra_result

    # Fallback: try objdump
    objdump_result = _try_objdump(binary_path, function)
    if objdump_result["success"]:
        return objdump_result

    # Final fallback: provide manual analysis instructions
    return _manual_fallback(binary_path, function)


def _try_ghidra(binary_path: str, function: str) -> Dict[str, Any]:
    """Attempt decompilation using Ghidra headless analyzer."""
    result: Dict[str, Any] = {
        "success": False,
        "decompiled_code": "",
        "functions": [],
        "tool_used": "ghidra",
    }

    # Look for Ghidra's analyzeHeadless
    ghidra_bin = shutil.which("analyzeHeadless")
    if not ghidra_bin:
        # Check common installation paths
        ghidra_home = os.environ.get("GHIDRA_HOME", "")
        if ghidra_home:
            candidate = Path(ghidra_home) / "support" / "analyzeHeadless"
            if candidate.exists():
                ghidra_bin = str(candidate)

    if not ghidra_bin:
        return result

    try:
        # Create a temporary project directory for Ghidra
        with tempfile.TemporaryDirectory(prefix="ghidra_ctf_") as tmp_dir:
            project_name = "ctf_analysis"
            output_file = Path(tmp_dir) / "decompiled.c"

            # Build Ghidra headless command
            # Uses a post-script to export decompiled code
            script_content = _ghidra_decompile_script(function, str(output_file))
            script_file = Path(tmp_dir) / "decompile_script.py"
            script_file.write_text(script_content, encoding="utf-8")

            cmd = [
                ghidra_bin,
                tmp_dir,
                project_name,
                "-import", binary_path,
                "-postScript", str(script_file),
                "-deleteProject",
                "-noanalysis" if function == "__all__" else "",
            ]
            # Remove empty strings from command
            cmd = [c for c in cmd if c]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if output_file.exists():
                decompiled = output_file.read_text(encoding="utf-8", errors="replace")
                result["success"] = True
                result["decompiled_code"] = decompiled
                result["functions"] = _extract_function_names(decompiled)
            elif proc.returncode == 0:
                # Ghidra ran but no output file - parse stdout
                result["success"] = True
                result["decompiled_code"] = proc.stdout[:10000]
                result["functions"] = _extract_function_names(proc.stdout)
            else:
                result["error"] = proc.stderr[:500] if proc.stderr else "Ghidra analysis failed"

    except subprocess.TimeoutExpired:
        result["error"] = "Ghidra analysis timed out (120s limit)"
    except (OSError, IOError) as exc:
        result["error"] = f"Ghidra execution error: {exc}"

    return result


def _try_objdump(binary_path: str, function: str) -> Dict[str, Any]:
    """Attempt disassembly using objdump."""
    result: Dict[str, Any] = {
        "success": False,
        "decompiled_code": "",
        "functions": [],
        "tool_used": "objdump",
    }

    objdump_bin = shutil.which("objdump")
    if not objdump_bin:
        return result

    try:
        # First, get the list of functions (symbols)
        sym_proc = subprocess.run(
            [objdump_bin, "-t", binary_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        functions: List[str] = []
        if sym_proc.returncode == 0:
            for line in sym_proc.stdout.splitlines():
                # Look for function symbols (F flag in objdump -t output)
                if " F " in line or " .text" in line:
                    parts = line.split()
                    if parts:
                        func_name = parts[-1]
                        if not func_name.startswith("."):
                            functions.append(func_name)

        # Disassemble the target function or full binary
        cmd = [objdump_bin, "-d", "-M", "intel", binary_path]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if proc.returncode != 0:
            result["error"] = proc.stderr[:500] if proc.stderr else "objdump failed"
            return result

        disassembly = proc.stdout

        # Extract the specific function if requested
        if function and function != "__all__":
            func_asm = _extract_function_disasm(disassembly, function)
            if func_asm:
                disassembly = func_asm

        result["success"] = True
        result["decompiled_code"] = disassembly[:20000]  # Limit output size
        result["functions"] = functions or _extract_function_names_from_disasm(disassembly)

    except subprocess.TimeoutExpired:
        result["error"] = "objdump timed out (30s limit)"
    except (OSError, IOError) as exc:
        result["error"] = f"objdump execution error: {exc}"

    return result


def _manual_fallback(binary_path: str, function: str) -> Dict[str, Any]:
    """Provide manual analysis instructions when no tools are available."""
    path = Path(binary_path)
    file_size = path.stat().st_size if path.exists() else 0

    instructions = (
        f"No decompilation tools available (Ghidra, objdump not found).\n"
        f"\n"
        f"Binary: {binary_path}\n"
        f"Size: {file_size} bytes\n"
        f"Target function: {function}\n"
        f"\n"
        f"Manual analysis suggestions:\n"
        f"1. Install Ghidra: https://ghidra-sre.org/\n"
        f"   Run: analyzeHeadless /tmp/project ctf -import {binary_path}\n"
        f"2. Install objdump (part of binutils):\n"
        f"   Run: objdump -d -M intel {binary_path}\n"
        f"3. Use IDA Free: https://hex-rays.com/ida-free/\n"
        f"4. Use radare2: r2 -A {binary_path}\n"
        f"5. Use Binary Ninja Cloud: https://cloud.binary.ninja/\n"
    )

    return {
        "success": False,
        "decompiled_code": instructions,
        "functions": [],
        "tool_used": "none",
        "error": "No decompilation tools available",
    }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _ghidra_decompile_script(function: str, output_path: str) -> str:
    """Generate a Ghidra Python script for decompilation."""
    return f'''# Ghidra decompile script (auto-generated)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

output_lines = []
fm = currentProgram.getFunctionManager()

target_func = "{function}"
functions_found = []

for func in fm.getFunctions(True):
    functions_found.append(func.getName())
    if target_func == "__all__" or func.getName() == target_func:
        results = decomp.decompileFunction(func, 60, monitor)
        if results.depiledFunction():
            output_lines.append(f"// Function: {{func.getName()}}")
            output_lines.append(results.getDecompiledFunction().getC())
            output_lines.append("")

with open("{output_path}", "w") as f:
    f.write("\\n".join(output_lines))
    f.write("\\n// Functions found: " + ", ".join(functions_found))
'''


def _extract_function_names(code: str) -> List[str]:
    """Extract function names from decompiled C code."""
    import re
    # Match C function definitions: return_type function_name(...)
    pattern = r'\b(?:void|int|char|long|unsigned|short|float|double|bool)\s+(\w+)\s*\('
    matches = re.findall(pattern, code)
    # Also match "// Function: name" comments from Ghidra output
    comment_pattern = r'// Function:\s+(\w+)'
    matches.extend(re.findall(comment_pattern, code))
    return list(dict.fromkeys(matches))  # Deduplicate preserving order


def _extract_function_names_from_disasm(disasm: str) -> List[str]:
    """Extract function names from objdump disassembly output."""
    import re
    # objdump format: "0000000000401000 <main>:"
    pattern = r'<(\w+)>:'
    matches = re.findall(pattern, disasm)
    return list(dict.fromkeys(matches))


def _extract_function_disasm(disasm: str, function: str) -> str:
    """Extract disassembly for a specific function from objdump output."""
    lines = disasm.splitlines()
    in_function = False
    func_lines: List[str] = []

    for line in lines:
        if f"<{function}>:" in line:
            in_function = True
            func_lines.append(line)
        elif in_function:
            if line.strip() == "" or (line and not line[0].isspace() and ":" in line and "<" in line):
                # End of function (next function header or blank line)
                if func_lines and line.strip() == "":
                    func_lines.append(line)
                    continue
                if "<" in line and ">:" in line:
                    break
            func_lines.append(line)

    return "\n".join(func_lines) if func_lines else ""


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------


@register
class DecompileTool(BaseTool):
    """Decompile/disassemble binary files for reverse engineering."""

    category = "ctf_reverse"
    external_binary = "objdump"

    @property
    def name(self) -> str:
        return "decompile"

    @property
    def description(self) -> str:
        return (
            "Decompile or disassemble a binary file. Uses Ghidra headless if available, "
            "falls back to objdump for disassembly. Returns decompiled code and function list."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file to decompile.",
                },
                "function": {
                    "type": "string",
                    "description": "Target function name to decompile (default: 'main').",
                    "default": "main",
                },
            },
            "required": ["binary_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        binary_path = kwargs.get("binary_path", "")
        function = kwargs.get("function", "main")

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

        exec_result = decompile(binary_path, function)

        if exec_result["success"]:
            func_count = len(exec_result["functions"])
            code_len = len(exec_result["decompiled_code"])
            summary = (
                f"Decompiled using {exec_result['tool_used']}: "
                f"{func_count} functions found, {code_len} chars of code"
            )
            return ToolResult(
                success=True,
                tool=self.name,
                summary=summary,
                parsed_data=exec_result,
                raw_output=exec_result["decompiled_code"][:2000],
            )
        else:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=exec_result.get("error", "Decompilation failed"),
                error=exec_result.get("error", "unknown_error"),
                parsed_data=exec_result,
            )
