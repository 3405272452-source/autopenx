"""Checksec tool: analyze binary protection mechanisms (NX, PIE, ASLR, Canary, RELRO).

Provides both a standalone function ``checksec(binary_path)`` and a registered
``ChecksecTool`` class for use in the tool registry.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import json
from pathlib import Path
from typing import Any, Dict

from ..base import BaseTool, ToolResult, register


def checksec(binary_path: str) -> dict:
    """Analyze binary protection mechanisms.

    Attempts to use the external ``checksec`` binary first. Falls back to
    parsing ELF headers directly if the external tool is unavailable.

    Args:
        binary_path: Path to the ELF binary to analyze.

    Returns:
        Dictionary with keys: nx, pie, canary, relro, arch, bits.
        On error, includes an 'error' key with a description.
    """
    if not binary_path:
        return {"error": "binary_path is required"}

    path = Path(binary_path)
    if not path.exists():
        return {"error": f"Binary not found: {binary_path}"}

    # Try external checksec binary first
    checksec_bin = shutil.which("checksec")
    if checksec_bin:
        try:
            proc = subprocess.run(
                [checksec_bin, f"--file={binary_path}", "--output=json"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    parsed = json.loads(proc.stdout.strip())
                    file_data = parsed.get(binary_path, parsed)
                    if isinstance(file_data, dict):
                        return {
                            "nx": "enabled" in str(file_data.get("nx", "")).lower(),
                            "pie": "enabled" in str(file_data.get("pie", "")).lower(),
                            "canary": "enabled" in str(file_data.get("canary", "")).lower(),
                            "relro": str(file_data.get("relro", "No RELRO")),
                            "arch": str(file_data.get("arch", "unknown")),
                            "bits": int(file_data.get("bits", 0)) if file_data.get("bits") else 0,
                            "source": "checksec_binary",
                        }
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass  # Fall through to manual parsing
        except (subprocess.TimeoutExpired, OSError):
            pass  # Fall through to manual parsing

    # Fallback: parse ELF headers manually
    result = _parse_elf_headers(binary_path)
    if "error" not in result:
        result["source"] = "elf_header_parser"
    return result


def _parse_elf_headers(binary_path: str) -> Dict[str, Any]:
    """Parse ELF headers manually to determine security protections."""
    result = {
        "nx": False,
        "pie": False,
        "canary": False,
        "relro": "No RELRO",
        "aslr": "Unknown (kernel setting)",
        "arch": "unknown",
        "bits": 0,
    }

    try:
        data = Path(binary_path).read_bytes()
    except (OSError, IOError) as e:
        return {**result, "error": str(e)}

    # Check ELF magic
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {**result, "error": "Not a valid ELF file"}

    # ELF class: 1=32-bit, 2=64-bit
    elf_class = data[4]
    bits = 64 if elf_class == 2 else 32
    result["bits"] = bits

    # Endianness: 1=little, 2=big
    endian = "<" if data[5] == 1 else ">"

    # e_type: 2=ET_EXEC, 3=ET_DYN (PIE)
    e_type = struct.unpack_from(f"{endian}H", data, 16)[0]
    result["pie"] = e_type == 3  # ET_DYN means PIE

    # Architecture
    e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
    arch_map = {
        0x03: "x86",
        0x3E: "x86_64",
        0x28: "ARM",
        0xB7: "AArch64",
        0x08: "MIPS",
    }
    result["arch"] = arch_map.get(e_machine, f"unknown(0x{e_machine:x})")

    if bits == 64:
        # 64-bit ELF header
        ph_off = struct.unpack_from(f"{endian}Q", data, 32)[0]
        ph_ent_size = struct.unpack_from(f"{endian}H", data, 54)[0]
        ph_num = struct.unpack_from(f"{endian}H", data, 56)[0]
        sh_off = struct.unpack_from(f"{endian}Q", data, 40)[0]
        sh_ent_size = struct.unpack_from(f"{endian}H", data, 58)[0]
        sh_num = struct.unpack_from(f"{endian}H", data, 60)[0]
        sh_strndx = struct.unpack_from(f"{endian}H", data, 62)[0]
    else:
        # 32-bit ELF header
        ph_off = struct.unpack_from(f"{endian}I", data, 28)[0]
        ph_ent_size = struct.unpack_from(f"{endian}H", data, 42)[0]
        ph_num = struct.unpack_from(f"{endian}H", data, 44)[0]
        sh_off = struct.unpack_from(f"{endian}I", data, 32)[0]
        sh_ent_size = struct.unpack_from(f"{endian}H", data, 46)[0]
        sh_num = struct.unpack_from(f"{endian}H", data, 48)[0]
        sh_strndx = struct.unpack_from(f"{endian}H", data, 50)[0]

    # Parse program headers for PT_GNU_STACK (NX) and PT_GNU_RELRO
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552
    PF_X = 0x1  # Execute flag

    has_relro = False
    for i in range(ph_num):
        off = ph_off + i * ph_ent_size
        if off + ph_ent_size > len(data):
            break
        if bits == 64:
            p_type = struct.unpack_from(f"{endian}I", data, off)[0]
            p_flags = struct.unpack_from(f"{endian}I", data, off + 4)[0]
        else:
            p_type = struct.unpack_from(f"{endian}I", data, off)[0]
            p_flags = struct.unpack_from(f"{endian}I", data, off + 24)[0]

        if p_type == PT_GNU_STACK:
            # NX enabled if stack is NOT executable
            result["nx"] = not bool(p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            has_relro = True

    # Parse section headers to detect canary (__stack_chk_fail) and full RELRO
    # Get section name string table
    dynamic_entries: Dict[int, int] = {}
    SHT_DYNAMIC = 6
    SHT_DYNSYM = 11

    canary_found = False
    full_relro = False

    # Read section headers to find .dynamic and .dynsym
    for i in range(sh_num):
        off = sh_off + i * sh_ent_size
        if off + sh_ent_size > len(data):
            break
        if bits == 64:
            sh_type = struct.unpack_from(f"{endian}I", data, off + 4)[0]
            sh_offset = struct.unpack_from(f"{endian}Q", data, off + 24)[0]
            sh_size = struct.unpack_from(f"{endian}Q", data, off + 32)[0]
            sh_entsize = struct.unpack_from(f"{endian}Q", data, off + 56)[0]
        else:
            sh_type = struct.unpack_from(f"{endian}I", data, off + 4)[0]
            sh_offset = struct.unpack_from(f"{endian}I", data, off + 16)[0]
            sh_size = struct.unpack_from(f"{endian}I", data, off + 20)[0]
            sh_entsize = struct.unpack_from(f"{endian}I", data, off + 36)[0]

        if sh_type == SHT_DYNAMIC and sh_entsize > 0:
            # Parse .dynamic for BIND_NOW (full RELRO indicator)
            DT_BIND_NOW = 24
            DT_FLAGS = 30
            DF_BIND_NOW = 0x8
            n_entries = sh_size // sh_entsize if sh_entsize else 0
            for j in range(n_entries):
                doff = sh_offset + j * sh_entsize
                if doff + sh_entsize > len(data):
                    break
                if bits == 64:
                    d_tag = struct.unpack_from(f"{endian}q", data, doff)[0]
                    d_val = struct.unpack_from(f"{endian}Q", data, doff + 8)[0]
                else:
                    d_tag = struct.unpack_from(f"{endian}i", data, doff)[0]
                    d_val = struct.unpack_from(f"{endian}I", data, doff + 4)[0]
                if d_tag == DT_BIND_NOW:
                    full_relro = True
                elif d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
                    full_relro = True

    # Check for __stack_chk_fail in binary data (canary indicator)
    if b"__stack_chk_fail" in data:
        canary_found = True

    result["canary"] = canary_found
    if has_relro and full_relro:
        result["relro"] = "Full RELRO"
    elif has_relro:
        result["relro"] = "Partial RELRO"
    else:
        result["relro"] = "No RELRO"

    return result


@register
class ChecksecTool(BaseTool):
    """Analyze binary protection mechanisms."""

    category = "ctf_pwn"
    external_binary = "checksec"

    @property
    def name(self) -> str:
        return "checksec"

    @property
    def description(self) -> str:
        return (
            "Analyze binary protection mechanisms: NX, PIE, ASLR, Stack Canary, RELRO. "
            "Uses the checksec binary if available, otherwise parses ELF headers directly."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the ELF binary to analyze",
                },
            },
            "required": ["binary_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        binary_path = kwargs.get("binary_path", "")
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

        # Try checksec binary first
        import shutil
        checksec_bin = shutil.which("checksec")
        if checksec_bin:
            try:
                proc = subprocess.run(
                    [checksec_bin, f"--file={binary_path}", "--output=json"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                raw = proc.stdout.strip()
                if proc.returncode == 0 and raw:
                    try:
                        parsed = json.loads(raw)
                        # checksec JSON output varies; normalize it
                        file_data = parsed.get(binary_path, parsed)
                        if isinstance(file_data, dict):
                            protections = {
                                "nx": file_data.get("nx", "unknown"),
                                "pie": file_data.get("pie", "unknown"),
                                "canary": file_data.get("canary", "unknown"),
                                "relro": file_data.get("relro", "unknown"),
                                "aslr": "kernel setting",
                                "source": "checksec_binary",
                            }
                            summary = (
                                f"NX={protections['nx']} PIE={protections['pie']} "
                                f"Canary={protections['canary']} RELRO={protections['relro']}"
                            )
                            return ToolResult(
                                success=True,
                                tool=self.name,
                                summary=summary,
                                raw_output=raw,
                                parsed_data=protections,
                            )
                    except json.JSONDecodeError:
                        pass  # Fall through to manual parsing
            except (subprocess.TimeoutExpired, OSError):
                pass  # Fall through to manual parsing

        # Fallback: parse ELF headers manually
        protections = _parse_elf_headers(binary_path)
        if "error" in protections:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=f"Failed to parse binary: {protections['error']}",
                error=protections["error"],
            )

        protections["source"] = "elf_header_parser"
        summary = (
            f"NX={protections['nx']} PIE={protections['pie']} "
            f"Canary={protections['canary']} RELRO={protections['relro']} "
            f"Arch={protections.get('arch', 'unknown')}/{protections.get('bits', 0)}-bit"
        )
        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            parsed_data=protections,
        )
