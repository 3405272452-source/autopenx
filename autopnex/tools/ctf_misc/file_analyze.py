"""File analysis tool: detect file types, extract embedded files, find strings.

Provides both a standalone function ``file_analyze(file_path, method)`` and a registered
``FileAnalyzeTool`` class for use in the tool registry.
"""
from __future__ import annotations

import shutil
import subprocess
import re
from pathlib import Path
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register


# Common magic byte signatures
MAGIC_SIGNATURES: Dict[str, bytes] = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "GIF87a": b"GIF87a",
    "GIF89a": b"GIF89a",
    "PDF": b"%PDF",
    "ZIP": b"PK\x03\x04",
    "RAR": b"Rar!\x1a\x07",
    "GZIP": b"\x1f\x8b",
    "BZ2": b"BZh",
    "7Z": b"7z\xbc\xaf\x27\x1c",
    "ELF": b"\x7fELF",
    "PE": b"MZ",
    "TIFF_LE": b"II\x2a\x00",
    "TIFF_BE": b"MM\x00\x2a",
    "BMP": b"BM",
    "WAV": b"RIFF",
    "MP3_ID3": b"ID3",
    "MP3_SYNC": b"\xff\xfb",
    "OGG": b"OggS",
    "FLAC": b"fLaC",
    "SQLite": b"SQLite format 3",
    "TAR": b"ustar",
}


def file_analyze(file_path: str, method: str = "auto") -> dict:
    """Analyze a file to detect type, embedded files, and extract strings.

    Args:
        file_path: Path to the file to analyze.
        method: Analysis method - "auto", "binwalk", "file_type", or "strings".

    Returns:
        Dictionary with keys: file_type, embedded_files, strings_found, hidden_data.
        On error, includes an 'error' key.
    """
    if not file_path:
        return {"error": "file_path is required", "file_type": "", "embedded_files": [], "strings_found": [], "hidden_data": False}

    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}", "file_type": "", "embedded_files": [], "strings_found": [], "hidden_data": False}

    result: Dict[str, Any] = {
        "file_type": "",
        "embedded_files": [],
        "strings_found": [],
        "hidden_data": False,
    }

    if method == "auto":
        # Run all methods
        result["file_type"] = _detect_file_type(path)
        result["embedded_files"] = _run_binwalk(path)
        result["strings_found"] = _extract_strings(path)
        result["hidden_data"] = len(result["embedded_files"]) > 1 or _check_hidden_data(path, result["file_type"])
    elif method == "binwalk":
        result["file_type"] = _detect_file_type(path)
        result["embedded_files"] = _run_binwalk(path)
        result["hidden_data"] = len(result["embedded_files"]) > 1
    elif method == "file_type":
        result["file_type"] = _detect_file_type(path)
    elif method == "strings":
        result["file_type"] = _detect_file_type(path)
        result["strings_found"] = _extract_strings(path)
    else:
        return {"error": f"Unknown method: {method}", "file_type": "", "embedded_files": [], "strings_found": [], "hidden_data": False}

    return result


def _detect_file_type(path: Path) -> str:
    """Detect file type using magic bytes."""
    try:
        data = path.read_bytes()[:64]
    except (OSError, IOError):
        return "unknown"

    if len(data) == 0:
        return "empty"

    for name, magic in MAGIC_SIGNATURES.items():
        if data.startswith(magic):
            return name

    # Check for TAR (magic at offset 257)
    try:
        full_data = path.read_bytes()
        if len(full_data) > 262 and full_data[257:262] == b"ustar":
            return "TAR"
    except (OSError, IOError):
        pass

    # Check if it's mostly printable text
    try:
        sample = path.read_bytes()[:1024]
        printable_ratio = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13)) / max(len(sample), 1)
        if printable_ratio > 0.85:
            return "text"
    except (OSError, IOError):
        pass

    return "unknown"


def _run_binwalk(path: Path) -> List[str]:
    """Run binwalk to find embedded files. Falls back to magic byte scanning."""
    binwalk_bin = shutil.which("binwalk")
    if binwalk_bin:
        try:
            proc = subprocess.run(
                [binwalk_bin, str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return _parse_binwalk_output(proc.stdout)
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Fallback: scan for magic bytes at various offsets
    return _scan_embedded_magic(path)


def _parse_binwalk_output(output: str) -> List[str]:
    """Parse binwalk text output into a list of found items."""
    results: List[str] = []
    lines = output.strip().split("\n")
    for line in lines:
        # binwalk output format: DECIMAL   HEXADECIMAL   DESCRIPTION
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("DECIMAL"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 3 and parts[0].isdigit():
            results.append(f"offset={parts[0]}: {parts[2]}")
    return results


def _scan_embedded_magic(path: Path) -> List[str]:
    """Scan file for embedded magic signatures (fallback when binwalk unavailable)."""
    results: List[str] = []
    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return results

    # Skip the first match (it's the file itself)
    for name, magic in MAGIC_SIGNATURES.items():
        if len(magic) < 2:
            continue
        offset = 0
        first_found = True
        while True:
            idx = data.find(magic, offset)
            if idx == -1:
                break
            if first_found and idx == 0:
                # Skip the file's own header
                first_found = False
                offset = idx + len(magic)
                continue
            first_found = False
            results.append(f"offset={idx}: {name} signature")
            offset = idx + len(magic)
            # Limit results
            if len(results) >= 20:
                return results

    return results


def _extract_strings(path: Path, min_length: int = 6, max_results: int = 50) -> List[str]:
    """Extract printable strings from file."""
    # Try external strings command first
    strings_bin = shutil.which("strings")
    if strings_bin:
        try:
            proc = subprocess.run(
                [strings_bin, "-n", str(min_length), str(path)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                lines = proc.stdout.strip().split("\n")
                return lines[:max_results]
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Fallback: manual string extraction
    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return []

    strings_found: List[str] = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings_found.append("".join(current))
                if len(strings_found) >= max_results:
                    break
            current = []

    # Don't forget the last string
    if len(current) >= min_length and len(strings_found) < max_results:
        strings_found.append("".join(current))

    return strings_found


def _check_hidden_data(path: Path, file_type: str) -> bool:
    """Check for signs of hidden data (e.g., data appended after file end)."""
    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return False

    if file_type == "PNG":
        # PNG should end with IEND chunk
        iend_pos = data.find(b"IEND")
        if iend_pos != -1:
            # IEND chunk is 4 bytes type + 4 bytes CRC after
            end_of_png = iend_pos + 4 + 4
            if end_of_png < len(data) - 1:
                return True

    elif file_type == "JPEG":
        # JPEG should end with FFD9
        eoi_pos = data.rfind(b"\xff\xd9")
        if eoi_pos != -1 and eoi_pos + 2 < len(data):
            return True

    elif file_type == "ZIP":
        # Check for data before the ZIP header
        zip_start = data.find(b"PK\x03\x04")
        if zip_start > 0:
            return True

    return False


@register
class FileAnalyzeTool(BaseTool):
    """Analyze files to detect type, embedded content, and extract strings."""

    category = "ctf_misc"
    external_binary = "binwalk"

    @property
    def name(self) -> str:
        return "file_analyze"

    @property
    def description(self) -> str:
        return (
            "Analyze a file to detect its type via magic bytes, find embedded files "
            "(using binwalk or fallback scanning), and extract printable strings. "
            "Useful for CTF Misc challenges involving file forensics."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to analyze",
                },
                "method": {
                    "type": "string",
                    "enum": ["auto", "binwalk", "file_type", "strings"],
                    "description": "Analysis method (default: auto)",
                },
            },
            "required": ["file_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        file_path = kwargs.get("file_path", "")
        method = kwargs.get("method", "auto")

        result = file_analyze(file_path, method)

        if "error" in result:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=result["error"],
                error=result["error"],
            )

        summary_parts = [f"Type: {result['file_type']}"]
        if result["embedded_files"]:
            summary_parts.append(f"Embedded: {len(result['embedded_files'])} items")
        if result["strings_found"]:
            summary_parts.append(f"Strings: {len(result['strings_found'])} found")
        if result["hidden_data"]:
            summary_parts.append("Hidden data detected!")

        return ToolResult(
            success=True,
            tool=self.name,
            summary=" | ".join(summary_parts),
            parsed_data=result,
        )
