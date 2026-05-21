"""SQLMap wrapper tool for automated SQL injection testing.

Provides a `run_sqlmap()` function that the LLM can call via `run_python`
to automate SQL injection detection and exploitation using sqlmap.

Usage (via run_python):
    from autopnex.tools.ctf_web.sqlmap_wrapper import run_sqlmap
    result = run_sqlmap("http://target/page?id=1")
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional


def _find_sqlmap() -> Optional[List[str]]:
    """Locate sqlmap executable. Returns command prefix or None."""
    # Check if sqlmap is on PATH
    if shutil.which("sqlmap"):
        return ["sqlmap"]
    # Check if python -m sqlmap works
    try:
        result = subprocess.run(
            [sys.executable, "-m", "sqlmap", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return [sys.executable, "-m", "sqlmap"]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def _extract_flags(text: str) -> List[str]:
    """Extract CTF flag patterns from sqlmap output."""
    patterns = [
        r'flag\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'HCTF\{[^}]+\}',
        r'DASCTF\{[^}]+\}',
        r'NCTF\{[^}]+\}',
        r'ACTF\{[^}]+\}',
        r'SCTF\{[^}]+\}',
        r'RCTF\{[^}]+\}',
        r'GWCTF\{[^}]+\}',
        r'BUUCTF\{[^}]+\}',
    ]
    flags: List[str] = []
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            val = m.group(0)
            if val not in flags:
                flags.append(val)
    return flags


def run_sqlmap(
    target_url: str,
    *,
    level: int = 1,
    risk: int = 1,
    timeout: int = 30,
    extra_args: Optional[List[str]] = None,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
) -> Dict[str, Any]:
    """Run sqlmap against a target URL and return structured results.

    Args:
        target_url: URL with injectable parameter (e.g. http://target/page?id=1)
        level: sqlmap level (1-5, default 1)
        risk: sqlmap risk (1-3, default 1)
        timeout: HTTP timeout in seconds (default 30)
        extra_args: Additional sqlmap arguments
        data: POST data string (e.g. "user=admin&pass=test")
        cookie: Cookie header value

    Returns:
        Dict with keys:
            success (bool): Whether sqlmap ran successfully
            stdout (str): Standard output from sqlmap
            stderr (str): Standard error from sqlmap
            flags_found (List[str]): Any CTF flags found in output
            error (str): Error message if sqlmap not available
            suggestion (str): Suggestion for fixing the error
    """
    cmd_prefix = _find_sqlmap()
    if cmd_prefix is None:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "flags_found": [],
            "error": "sqlmap not installed",
            "suggestion": "pip install sqlmap",
        }

    # Build command
    cmd = cmd_prefix + [
        "-u", target_url,
        "--batch",
        "--dump",
        f"--level={level}",
        f"--risk={risk}",
        f"--timeout={timeout}",
    ]

    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 60,  # Give sqlmap extra time beyond HTTP timeout
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = stdout + "\n" + stderr
        flags = _extract_flags(combined)

        return {
            "success": result.returncode == 0,
            "stdout": stdout[-5000:] if len(stdout) > 5000 else stdout,
            "stderr": stderr[-2000:] if len(stderr) > 2000 else stderr,
            "flags_found": flags,
            "error": "" if result.returncode == 0 else f"sqlmap exited with code {result.returncode}",
            "suggestion": "",
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "flags_found": [],
            "error": f"sqlmap timed out after {timeout + 60} seconds",
            "suggestion": "Try reducing --level or --risk, or increase timeout",
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "flags_found": [],
            "error": f"Failed to run sqlmap: {type(e).__name__}: {e}",
            "suggestion": "Check sqlmap installation",
        }
