"""CTF Environment Probe - check runtime readiness before solving.

Validates Python dependencies, external binaries, network connectivity,
workspace state, and debugger/decompiler availability.
"""
from __future__ import annotations

import importlib
import logging
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import RuntimeConfig

log = logging.getLogger("autopnex.ctf.environment_probe")


@dataclass
class ProbeResult:
    """Result of an environment probe check."""

    ready: bool
    missing: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ready": self.ready,
            "missing": self.missing,
            "warnings": self.warnings,
            "details": self.details,
        }


class EnvironmentProbe:
    """Probe the local environment for CTF solving readiness."""

    def __init__(self, runtime_config: Optional[RuntimeConfig] = None) -> None:
        self.runtime_config = runtime_config
        self._cache: Optional[ProbeResult] = None

    # -- public API --------------------------------------------------------

    def probe(self) -> ProbeResult:
        """Run full environment probe and cache result."""
        if self._cache is not None:
            return self._cache

        missing: List[str] = []
        warnings: List[str] = []
        details: Dict[str, Any] = {}

        # Python packages
        py_packages = self._check_python_packages()
        details["python_packages"] = py_packages
        for pkg, ok in py_packages.items():
            if not ok:
                missing.append(f"python:{pkg}")

        # External binaries
        binaries = self._check_external_binaries()
        details["external_binaries"] = binaries
        for name, ok in binaries.items():
            if not ok:
                warnings.append(f"binary:{name}")

        # Network
        net_ok = self._check_network()
        details["network_reachable"] = net_ok
        if not net_ok:
            warnings.append("network:external_reachability")

        # Workspace
        ws_ok, ws_path = self._check_workspace()
        details["workspace_ok"] = ws_ok
        details["workspace_path"] = ws_path
        if not ws_ok:
            missing.append(f"workspace:{ws_path}")

        # Debugger / decompiler presence (informational)
        debug_tools = self._check_debug_tools()
        details["debug_tools"] = debug_tools

        ready = len(missing) == 0
        self._cache = ProbeResult(
            ready=ready,
            missing=missing,
            warnings=warnings,
            details=details,
        )
        return self._cache

    # -- checks ------------------------------------------------------------

    @staticmethod
    def _check_python_packages() -> Dict[str, bool]:
        packages = [
            "requests",
            "cryptography",
            "pycryptodome",
            "pwntools",
            "z3",
        ]
        results: Dict[str, bool] = {}
        for pkg in packages:
            try:
                importlib.import_module(pkg)
                results[pkg] = True
            except ImportError:
                results[pkg] = False
        return results

    @staticmethod
    def _check_external_binaries() -> Dict[str, bool]:
        binaries = [
            "python",
            "pip",
            "strings",
            "file",
            "objdump",
            "readelf",
        ]
        return {name: shutil.which(name) is not None for name in binaries}

    @staticmethod
    def _check_network(host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0) -> bool:
        try:
            socket.setdefaulttimeout(timeout)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
            return True
        except OSError:
            return False
        finally:
            socket.setdefaulttimeout(None)

    def _check_workspace(self) -> tuple:
        if self.runtime_config is None:
            return True, ""
        ws_dir = Path(self.runtime_config.ctf_workspace_dir)
        try:
            ws_dir.mkdir(parents=True, exist_ok=True)
            test_file = ws_dir / ".probe"
            test_file.write_text("ok")
            test_file.unlink()
            return True, str(ws_dir)
        except OSError as e:
            return False, str(e)

    @staticmethod
    def _check_debug_tools() -> Dict[str, bool]:
        tools: Dict[str, bool] = {}
        # Check known tool paths from environment or defaults
        for env_var, name in [
            ("JADX_PATH", "jadx"),
            ("IDA_PATH", "ida"),
            ("GDB_PATH", "gdb"),
        ]:
            path = os.environ.get(env_var, "")
            tools[name] = bool(path) and Path(path).exists()
        # Also check PATH
        for name in ["gdb", "lldb"]:
            if name not in tools:
                tools[name] = shutil.which(name) is not None
        return tools
