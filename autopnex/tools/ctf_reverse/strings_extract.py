"""Strings extraction tool for CTF reverse engineering challenges.

Extracts printable strings from binary files with smart filtering:
- Flag pattern detection
- URL and path extraction
- Interesting keyword highlighting

Pure Python implementation — no external dependencies required.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Set

from ..base import BaseTool, ToolResult, register


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Patterns that suggest flag candidates
FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'CTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'[a-zA-Z]+\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?]+\}'),
    re.compile(r'flag[-_]?[a-f0-9]{32}', re.IGNORECASE),
]

# Patterns for interesting strings
URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')
PATH_PATTERN = re.compile(r'(?:/[a-zA-Z0-9._\-]+){2,}')
IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

# Keywords that are interesting in CTF context
INTERESTING_KEYWORDS = {
    "password", "passwd", "secret", "key", "token", "admin",
    "root", "shell", "exec", "system", "popen", "eval",
    "decrypt", "encrypt", "cipher", "hash", "md5", "sha",
    "base64", "encode", "decode", "xor", "aes", "rsa",
    "flag", "ctf", "hidden", "backdoor", "debug",
    "strcmp", "strncmp", "memcmp", "check", "verify",
    "correct", "wrong", "success", "fail", "win", "lose",
    "/bin/sh", "/bin/bash", "/flag", "/home",
}


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def strings_extract(
    binary_path: str,
    min_length: int = 4,
    encoding: str = "auto",
) -> dict:
    """Extract printable strings from a binary file.

    Args:
        binary_path: Path to the binary file.
        min_length: Minimum string length to extract (default: 4).
        encoding: Encoding to use: "ascii", "utf-16-le", "utf-16-be", or "auto" (all).

    Returns:
        dict with keys: strings, flag_candidates, interesting, total_count.
    """
    result: Dict[str, Any] = {
        "strings": [],
        "flag_candidates": [],
        "interesting": [],
        "total_count": 0,
    }

    if not binary_path:
        result["error"] = "binary_path is required"
        return result

    path = Path(binary_path)
    if not path.exists():
        result["error"] = f"File not found: {binary_path}"
        return result

    try:
        data = path.read_bytes()
    except (OSError, IOError) as exc:
        result["error"] = f"Failed to read file: {exc}"
        return result

    # Enforce minimum length bounds
    min_length = max(1, min(min_length, 100))

    # Extract strings based on encoding
    all_strings: List[str] = []

    if encoding in ("auto", "ascii"):
        all_strings.extend(_extract_ascii_strings(data, min_length))

    if encoding in ("auto", "utf-16-le"):
        all_strings.extend(_extract_utf16_strings(data, min_length, "little"))

    if encoding in ("auto", "utf-16-be"):
        all_strings.extend(_extract_utf16_strings(data, min_length, "big"))

    # Deduplicate while preserving order
    seen: Set[str] = set()
    unique_strings: List[str] = []
    for s in all_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append(s)

    # Classify strings
    flag_candidates: List[str] = []
    interesting: List[str] = []

    for s in unique_strings:
        # Check for flag patterns
        is_flag = False
        for pattern in FLAG_PATTERNS:
            if pattern.search(s):
                flag_candidates.append(s)
                is_flag = True
                break

        if is_flag:
            continue

        # Check for interesting strings
        if _is_interesting(s):
            interesting.append(s)

    result["strings"] = unique_strings
    result["flag_candidates"] = flag_candidates
    result["interesting"] = interesting
    result["total_count"] = len(unique_strings)

    return result


# ---------------------------------------------------------------------------
# String extraction helpers
# ---------------------------------------------------------------------------


def _extract_ascii_strings(data: bytes, min_length: int) -> List[str]:
    """Extract ASCII printable strings from binary data."""
    strings: List[str] = []
    current: List[str] = []

    for byte in data:
        # Printable ASCII range (0x20-0x7E) plus common whitespace
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        elif byte in (0x09, 0x0A, 0x0D):  # tab, newline, carriage return
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current).strip())
            current = []

    # Don't forget the last string
    if len(current) >= min_length:
        strings.append("".join(current).strip())

    # Filter out empty strings after stripping
    return [s for s in strings if len(s) >= min_length]


def _extract_utf16_strings(data: bytes, min_length: int, endian: str) -> List[str]:
    """Extract UTF-16 encoded strings from binary data."""
    strings: List[str] = []
    current: List[str] = []

    # Process pairs of bytes
    step = 2
    for i in range(0, len(data) - 1, step):
        if endian == "little":
            char_val = data[i] | (data[i + 1] << 8)
        else:
            char_val = (data[i] << 8) | data[i + 1]

        if 0x20 <= char_val <= 0x7E:
            current.append(chr(char_val))
        elif char_val in (0x09, 0x0A, 0x0D):
            current.append(chr(char_val))
        else:
            if len(current) >= min_length:
                strings.append("".join(current).strip())
            current = []

    if len(current) >= min_length:
        strings.append("".join(current).strip())

    return [s for s in strings if len(s) >= min_length]


def _is_interesting(s: str) -> bool:
    """Determine if a string is interesting for CTF analysis."""
    s_lower = s.lower()

    # Check keywords
    for keyword in INTERESTING_KEYWORDS:
        if keyword in s_lower:
            return True

    # Check URL pattern
    if URL_PATTERN.search(s):
        return True

    # Check path pattern
    if PATH_PATTERN.search(s):
        return True

    # Check IP address
    if IP_PATTERN.search(s):
        return True

    # Check for hex-encoded data (potential encoded flags)
    if re.match(r'^[0-9a-fA-F]{16,}$', s):
        return True

    # Check for base64-like strings (long alphanumeric with padding)
    if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s):
        return True

    return False


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------


@register
class StringsExtractTool(BaseTool):
    """Extract and analyze strings from binary files."""

    category = "ctf_reverse"

    @property
    def name(self) -> str:
        return "strings_extract"

    @property
    def description(self) -> str:
        return (
            "Extract printable strings from binary files with smart filtering. "
            "Identifies flag candidates, URLs, paths, and interesting keywords. "
            "Pure Python implementation — no external tools required."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file to analyze.",
                },
                "min_length": {
                    "type": "integer",
                    "description": "Minimum string length to extract (default: 4).",
                    "default": 4,
                },
                "encoding": {
                    "type": "string",
                    "description": "Encoding: 'ascii', 'utf-16-le', 'utf-16-be', or 'auto' (default: 'auto').",
                    "default": "auto",
                    "enum": ["auto", "ascii", "utf-16-le", "utf-16-be"],
                },
            },
            "required": ["binary_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        binary_path = kwargs.get("binary_path", "")
        min_length = int(kwargs.get("min_length", 4))
        encoding = kwargs.get("encoding", "auto")

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
                summary=f"File not found: {binary_path}",
                error="file_not_found",
            )

        exec_result = strings_extract(binary_path, min_length, encoding)

        if "error" in exec_result:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=exec_result["error"],
                error=exec_result["error"],
            )

        total = exec_result["total_count"]
        flags = len(exec_result["flag_candidates"])
        interesting = len(exec_result["interesting"])

        summary = (
            f"Extracted {total} strings: "
            f"{flags} flag candidates, {interesting} interesting"
        )

        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            parsed_data={
                "total_count": total,
                "flag_candidates": exec_result["flag_candidates"],
                "interesting": exec_result["interesting"],
                "strings_sample": exec_result["strings"][:50],
            },
            raw_output="\n".join(exec_result["strings"][:100]),
        )
