"""ROP chain generation tool: find useful gadgets using ROPgadget.

Provides both a standalone function ``rop_chain(binary_path, target)`` and a
registered ``ROPChainTool`` class for use in the tool registry.

NOTE: This is a template/helper. Actual exploitation requires pwntools at runtime.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register

# Gadget patterns we care about for common ROP chains
USEFUL_GADGET_PATTERNS = [
    r"pop rdi\s*;?\s*ret",
    r"pop rsi\s*;?\s*ret",
    r"pop rdx\s*;?\s*ret",
    r"pop rax\s*;?\s*ret",
    r"pop rbp\s*;?\s*ret",
    r"pop rsp\s*;?\s*ret",
    r"pop rcx\s*;?\s*ret",
    r"pop rbx\s*;?\s*ret",
    r"syscall\s*;?\s*ret",
    r"int 0x80\s*;?\s*ret",
    r"mov rdi,\s*rsp",
    r"xor rax,\s*rax\s*;?\s*ret",
    r"xor eax,\s*eax\s*;?\s*ret",
    r"ret$",
    r"leave\s*;?\s*ret",
    r"pop rdi\s*;.*ret",
    r"pop rsi\s*;.*ret",
]


def _parse_ropgadget_output(output: str) -> List[Dict[str, str]]:
    """Parse ROPgadget output into a list of gadget dicts."""
    gadgets = []
    for line in output.splitlines():
        line = line.strip()
        # ROPgadget format: "0x0000000000401234 : pop rdi ; ret"
        match = re.match(r"(0x[0-9a-fA-F]+)\s*:\s*(.+)", line)
        if match:
            addr = match.group(1)
            insns = match.group(2).strip()
            gadgets.append({"address": addr, "gadget": insns})
    return gadgets


def _filter_useful_gadgets(gadgets: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Filter gadgets to only the most useful ones for ROP chains."""
    useful = []
    seen_gadgets: set = set()
    for g in gadgets:
        insns = g["gadget"].lower()
        for pattern in USEFUL_GADGET_PATTERNS:
            if re.search(pattern, insns, re.IGNORECASE):
                key = insns
                if key not in seen_gadgets:
                    seen_gadgets.add(key)
                    useful.append(g)
                break
    return useful


def _build_chain_template(target: str, gadgets: List[Dict[str, str]]) -> Dict[str, Any]:
    """Build a ROP chain template based on target strategy and available gadgets.

    Returns a dict with chain layout and payload template string.
    """
    chain: List[str] = []
    payload_lines: List[str] = []

    # Build a lookup for quick gadget search
    gadget_lookup: Dict[str, str] = {}
    for g in gadgets:
        gadget_lookup[g["gadget"].lower().strip()] = g["address"]

    if target in ("system", "system_binsh"):
        # ret2system: pop rdi; ret -> /bin/sh -> system
        pop_rdi = None
        ret_gadget = None
        for g in gadgets:
            insns = g["gadget"].lower()
            if "pop rdi" in insns and "ret" in insns and pop_rdi is None:
                pop_rdi = g["address"]
            if insns.strip() == "ret" and ret_gadget is None:
                ret_gadget = g["address"]

        if ret_gadget:
            chain.append(f"ret  # stack alignment ({ret_gadget})")
            payload_lines.append(f"payload += p64({ret_gadget})  # ret (alignment)")
        if pop_rdi:
            chain.append(f"pop rdi; ret  # load /bin/sh address ({pop_rdi})")
            payload_lines.append(f"payload += p64({pop_rdi})  # pop rdi; ret")
            chain.append("/bin/sh address")
            payload_lines.append("payload += p64(binsh_addr)  # /bin/sh string")
        chain.append("system() address")
        payload_lines.append("payload += p64(system_addr)  # system()")

    elif target == "execve":
        # execve syscall: rax=59, rdi=/bin/sh, rsi=0, rdx=0
        for reg in ["rdi", "rsi", "rdx", "rax"]:
            for g in gadgets:
                if f"pop {reg}" in g["gadget"].lower():
                    chain.append(f"pop {reg}; ret ({g['address']})")
                    payload_lines.append(f"payload += p64({g['address']})  # pop {reg}; ret")
                    if reg == "rdi":
                        chain.append("/bin/sh address")
                        payload_lines.append("payload += p64(binsh_addr)")
                    elif reg == "rax":
                        chain.append("59 (execve syscall number)")
                        payload_lines.append("payload += p64(59)")
                    else:
                        chain.append("0 (NULL)")
                        payload_lines.append("payload += p64(0)")
                    break
        chain.append("syscall; ret")
        payload_lines.append("payload += p64(syscall_addr)  # syscall")

    else:
        # Generic: just list available gadgets
        for g in gadgets[:10]:
            chain.append(f"{g['gadget']} ({g['address']})")

    payload_template = "\n".join(payload_lines) if payload_lines else "# No suitable gadgets found for automatic chain generation"

    return {"chain": chain, "payload_template": payload_template}


def rop_chain(binary_path: str, target: str = "system") -> dict:
    """Generate basic ROP chain structure for a binary.

    Searches for useful gadgets using ROPgadget (if available) and builds
    a chain layout for the specified target strategy.

    Args:
        binary_path: Path to the ELF binary to analyze.
        target: ROP chain target strategy. One of 'system', 'system_binsh',
                'execve', 'ret2libc'. Defaults to 'system'.

    Returns:
        Dictionary with keys:
        - gadgets: List[dict] - found useful gadgets with address and instruction
        - chain: List[str] - ordered chain layout description
        - payload_template: str - Python code template for building the payload

    NOTE: This is a template/helper. Actual exploitation requires pwntools at runtime.
    """
    if not binary_path:
        return {"gadgets": [], "chain": [], "payload_template": "", "error": "binary_path is required"}

    path = Path(binary_path)
    if not path.exists():
        return {"gadgets": [], "chain": [], "payload_template": "", "error": f"Binary not found: {binary_path}"}

    # Normalize target
    if target in ("system", "system_binsh", "ret2libc"):
        effective_target = "system_binsh"
    else:
        effective_target = target

    # Try ROPgadget
    ropgadget_bin = shutil.which("ROPgadget") or shutil.which("ropgadget")
    all_gadgets: List[Dict[str, str]] = []

    if ropgadget_bin:
        try:
            proc = subprocess.run(
                [ropgadget_bin, "--binary", binary_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            all_gadgets = _parse_ropgadget_output(proc.stdout)
        except (subprocess.TimeoutExpired, OSError):
            pass

    useful_gadgets = _filter_useful_gadgets(all_gadgets)

    # Build chain template
    template = _build_chain_template(effective_target, useful_gadgets)

    return {
        "gadgets": useful_gadgets,
        "chain": template["chain"],
        "payload_template": template["payload_template"],
    }


@register
class ROPChainTool(BaseTool):
    """Find ROP gadgets in a binary using ROPgadget."""

    category = "ctf_pwn"
    external_binary = "ROPgadget"

    @property
    def name(self) -> str:
        return "rop_chain"

    @property
    def description(self) -> str:
        return (
            "Find ROP gadgets in a binary using ROPgadget. "
            "Returns useful gadgets (pop rdi, pop rsi, ret, syscall, etc.) "
            "for constructing ROP chains to bypass NX/DEP."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary to search for gadgets",
                },
                "target": {
                    "type": "string",
                    "description": "ROP chain target strategy (e.g. system_binsh, execve, ret2libc)",
                    "default": "system_binsh",
                },
            },
            "required": ["binary_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        binary_path = kwargs.get("binary_path", "")
        target = kwargs.get("target", "system_binsh")

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

        import shutil
        ropgadget_bin = shutil.which("ROPgadget") or shutil.which("ropgadget")

        if not ropgadget_bin:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=(
                    "ROPgadget is not installed. Install with: pip install ROPgadget\n"
                    "Alternatively use: ropper, pwntools (ROP class), or radare2 (r2 /path/binary)"
                ),
                error="missing_binary:ROPgadget",
                parsed_data={
                    "binary_path": binary_path,
                    "target": target,
                    "gadgets": [],
                    "install_hint": "pip install ROPgadget",
                },
            )

        try:
            proc = subprocess.run(
                [ropgadget_bin, "--binary", binary_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            raw_output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="ROPgadget timed out (binary may be too large)",
                error="timeout",
            )
        except OSError as e:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=f"Failed to run ROPgadget: {e}",
                error=str(e),
            )

        all_gadgets = _parse_ropgadget_output(proc.stdout)
        useful_gadgets = _filter_useful_gadgets(all_gadgets)

        # Build target-specific hints
        hints: List[str] = []
        if target == "system_binsh":
            hints = [
                "Look for: pop rdi ; ret  (to set first argument = /bin/sh address)",
                "Look for: ret  (stack alignment for 64-bit)",
                "Need: system() address from libc or PLT",
                "Need: /bin/sh string address in binary or libc",
            ]
        elif target == "execve":
            hints = [
                "Look for: pop rdi ; ret  (filename = /bin/sh)",
                "Look for: pop rsi ; ret  (argv = NULL)",
                "Look for: pop rdx ; ret  (envp = NULL)",
                "Look for: pop rax ; ret  (syscall number = 59 for execve)",
                "Look for: syscall ; ret",
            ]
        elif target == "ret2libc":
            hints = [
                "Look for: pop rdi ; ret  (to set argument)",
                "Look for: ret  (stack alignment)",
                "Need: libc base address (via leak)",
                "Need: system() and /bin/sh offsets in libc",
            ]

        summary = (
            f"Found {len(all_gadgets)} total gadgets, {len(useful_gadgets)} useful "
            f"for target={target} in {binary_path}"
        )

        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            raw_output=raw_output[:3000],
            parsed_data={
                "binary_path": binary_path,
                "target": target,
                "total_gadgets": len(all_gadgets),
                "useful_gadgets": useful_gadgets,
                "hints": hints,
            },
        )
