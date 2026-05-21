"""Persistent Python REPL — maintains state across multiple executions."""
from __future__ import annotations

import contextlib
import io
import sys
from typing import Any, Dict, List


class PersistentREPL:
    """A Python REPL that maintains variable state across calls.

    Unlike run_python (which creates a new subprocess each time), this REPL
    keeps variables alive between calls. Useful for multi-step exploits:

    Call 1: import requests; r = requests.get('http://target')
    Call 2: print(r.cookies)  # r is still available!
    Call 3: r2 = requests.post('http://target', cookies=r.cookies, data=...)
    """

    def __init__(self) -> None:
        self._globals: Dict[str, Any] = {"__builtins__": __builtins__}
        self._locals: Dict[str, Any] = {}

    def execute(self, code: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute code in the persistent namespace.

        Returns: {success, stdout, stderr, variables}
        """
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                exec(code, self._globals, self._locals)
            return {
                "success": True,
                "stdout": stdout_capture.getvalue(),
                "stderr": stderr_capture.getvalue(),
                "variables": list(self._locals.keys())[:20],
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": stdout_capture.getvalue(),
                "stderr": f"{type(e).__name__}: {e}",
                "variables": list(self._locals.keys())[:20],
            }

    def reset(self) -> None:
        """Clear all state."""
        self._globals = {"__builtins__": __builtins__}
        self._locals = {}
