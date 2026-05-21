"""Pwn CTF Capability - exploit binary challenges via pwntools, GDB, and script generation.

Supports local binary execution, remote socket interaction, and
automatic checksec-style baseline identification.
"""
from __future__ import annotations

import logging
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import CTFCapability

log = logging.getLogger("autopnex.ctf.capabilities.pwn")


class PwnCTFCapability(CTFCapability):
    name = "pwn"

    def suggest_tools(self) -> Dict[str, Any]:
        return {
            "recommended_tools": [
                "file_analyze",
                "run_python",
                "run_tool_script",
                "ctf_tool_manager",
                "ctf_knowledge_search",
            ]
        }

    def run_preflight(self, agent: Any) -> None:
        """Run checksec-style triage on attached binaries."""
        if not agent._files:
            return
        for file_path in agent._files:
            baseline = self._checksec_baseline(file_path)
            if baseline:
                agent._messages.append({
                    "role": "user",
                    "content": (
                        f"Binary baseline for {Path(file_path).name}:\n"
                        + self._format_baseline(baseline)
                    ),
                })
                agent._state.add_step(0, "pwn_baseline", {"file": file_path}, str(baseline)[:500])

    def run_helpers(
        self,
        *,
        agent: Any,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if tool_name == "file_analyze":
            file_path = tool_args.get("file_path", "")
            if file_path and Path(file_path).exists():
                baseline = self._checksec_baseline(file_path)
                if baseline:
                    return {
                        "helper": "pwn_baseline",
                        "file": file_path,
                        **baseline,
                    }
        return None

    # -- baseline ----------------------------------------------------------

    @staticmethod
    def _checksec_baseline(file_path: str) -> Optional[Dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            return None

        data = path.read_bytes()
        if data[:4] != b"\x7fELF":
            return None  # Not ELF

        baseline: Dict[str, Any] = {
            "arch": "unknown",
            "bits": 32,
            "endian": "little",
            "relro": "None",
            "canary": False,
            "nx": True,
            "pie": False,
            "rpath": False,
            "runpath": False,
            "stripped": False,
        }

        # Use file command for arch
        if shutil.which("file"):
            try:
                out = subprocess.run(
                    ["file", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                text = out.stdout
                if "64-bit" in text:
                    baseline["bits"] = 64
                if "32-bit" in text:
                    baseline["bits"] = 32
                if "ARM" in text:
                    baseline["arch"] = "arm"
                elif "x86-64" in text or "64-bit" in text:
                    baseline["arch"] = "x86-64"
                elif "80386" in text or "32-bit" in text:
                    baseline["arch"] = "i386"
                if "MSB" in text:
                    baseline["endian"] = "big"
                if "stripped" in text:
                    baseline["stripped"] = True
            except Exception:
                pass

        # Parse ELF headers for protections
        if shutil.which("readelf"):
            try:
                out = subprocess.run(
                    ["readelf", "-l", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                text = out.stdout
                if "GNU_STACK" in text:
                    baseline["nx"] = "RWE" not in text
                if "GNU_RELRO" in text:
                    baseline["relro"] = "Full" if "BIND_NOW" in text else "Partial"

                dyn = subprocess.run(
                    ["readelf", "-d", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                dyn_text = dyn.stdout
                if "RPATH" in dyn_text:
                    baseline["rpath"] = True
                if "RUNPATH" in dyn_text:
                    baseline["runpath"] = True

                sym = subprocess.run(
                    ["nm", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                sym_text = sym.stdout
                baseline["canary"] = "__stack_chk_fail" in sym_text
            except Exception:
                pass

        # PIE detection via file type
        try:
            out = subprocess.run(
                ["readelf", "-h", str(path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            h_text = out.stdout
            if "DYN" in h_text:
                baseline["pie"] = True
        except Exception:
            pass

        return baseline

    @staticmethod
    def _format_baseline(baseline: Dict[str, Any]) -> str:
        parts = [
            f"- Arch: {baseline.get('arch', '?')} ({baseline.get('bits', '?')}-bit)",
            f"- RELRO: {baseline.get('relro', '?')}",
            f"- Stack Canary: {'Yes' if baseline.get('canary') else 'No'}",
            f"- NX: {'Yes' if baseline.get('nx') else 'No'}",
            f"- PIE: {'Yes' if baseline.get('pie') else 'No'}",
            f"- Stripped: {'Yes' if baseline.get('stripped') else 'No'}",
        ]
        return "\n".join(parts)

    # -- script generation helpers ------------------------------------------

    @staticmethod
    def generate_pwntools_stub(target: str, baseline: Dict[str, Any]) -> str:
        """Generate a minimal pwntools exploit stub."""
        is_remote = target.startswith("nc ") or ":" in target and not Path(target).exists()

        lines: List[str] = [
            "from pwn import *",
            "",
        ]

        if is_remote:
            host, port = PwnCTFCapability._parse_remote(target)
            lines.extend([
                f"p = remote('{host}', {port})",
            ])
        else:
            lines.extend([
                f"p = process('./{Path(target).name}')",
            ])

        lines.extend([
            "",
            "# TODO: build payload based on baseline",
            f"# Arch: {baseline.get('arch', '?')}, Bits: {baseline.get('bits', '?')}",
            f"# Canary: {baseline.get('canary')}, NX: {baseline.get('nx')}, PIE: {baseline.get('pie')}",
            "",
            "p.interactive()",
        ])
        return "\n".join(lines)

    @staticmethod
    def _parse_remote(target: str) -> tuple:
        """Parse 'host:port' or 'nc host port' into (host, port)."""
        if target.startswith("nc "):
            parts = target.split()
            if len(parts) >= 3:
                return parts[1], int(parts[2])
        if ":" in target:
            host, port = target.rsplit(":", 1)
            return host, int(port)
        return "127.0.0.1", 1337
