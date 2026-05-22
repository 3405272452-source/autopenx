"""Steganography analysis tool: detect hidden data in images.

Provides both a standalone function ``stego_analyze(image_path, method)`` and a registered
``StegoAnalyzeTool`` class for use in the tool registry.
"""
from __future__ import annotations

import shutil
import subprocess
import re
from pathlib import Path
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register


def stego_analyze(image_path: str, method: str = "auto") -> dict:
    """Analyze an image for hidden steganographic data.

    Args:
        image_path: Path to the image file to analyze.
        method: Analysis method - "auto", "exiftool", "strings", "steghide", "zsteg".

    Returns:
        Dictionary with keys: hidden_data_found, method, extracted_data, metadata.
        On error, includes an 'error' key.
    """
    if not image_path:
        return {"error": "image_path is required", "hidden_data_found": False, "method": "", "extracted_data": "", "metadata": {}}

    path = Path(image_path)
    if not path.exists():
        return {"error": f"File not found: {image_path}", "hidden_data_found": False, "method": "", "extracted_data": "", "metadata": {}}

    result: Dict[str, Any] = {
        "hidden_data_found": False,
        "method": method,
        "extracted_data": "",
        "metadata": {},
    }

    if method == "auto":
        # Run all available methods
        metadata = _run_exiftool(path)
        result["metadata"] = metadata

        # Check for anomalies in metadata
        anomalies = _check_metadata_anomalies(metadata, path)
        if anomalies:
            result["hidden_data_found"] = True
            result["extracted_data"] = "; ".join(anomalies)
            result["method"] = "metadata_anomaly"

        # Try strings search for flags/hidden text
        strings_result = _search_strings(path)
        if strings_result:
            result["hidden_data_found"] = True
            if result["extracted_data"]:
                result["extracted_data"] += "; " + strings_result
            else:
                result["extracted_data"] = strings_result
            result["method"] = "strings"

        # Try steghide (for JPEG/BMP)
        steghide_result = _run_steghide(path)
        if steghide_result:
            result["hidden_data_found"] = True
            result["extracted_data"] = steghide_result
            result["method"] = "steghide"

        # Try zsteg (for PNG/BMP)
        zsteg_result = _run_zsteg(path)
        if zsteg_result:
            result["hidden_data_found"] = True
            result["extracted_data"] = zsteg_result
            result["method"] = "zsteg"

        # File size anomaly detection
        size_anomaly = _check_file_size_anomaly(path)
        if size_anomaly and not result["hidden_data_found"]:
            result["hidden_data_found"] = True
            result["extracted_data"] = size_anomaly
            result["method"] = "size_anomaly"

    elif method == "exiftool":
        metadata = _run_exiftool(path)
        result["metadata"] = metadata
        anomalies = _check_metadata_anomalies(metadata, path)
        if anomalies:
            result["hidden_data_found"] = True
            result["extracted_data"] = "; ".join(anomalies)
    elif method == "strings":
        strings_result = _search_strings(path)
        if strings_result:
            result["hidden_data_found"] = True
            result["extracted_data"] = strings_result
    elif method == "steghide":
        steghide_result = _run_steghide(path)
        if steghide_result:
            result["hidden_data_found"] = True
            result["extracted_data"] = steghide_result
    elif method == "zsteg":
        zsteg_result = _run_zsteg(path)
        if zsteg_result:
            result["hidden_data_found"] = True
            result["extracted_data"] = zsteg_result
    else:
        return {"error": f"Unknown method: {method}", "hidden_data_found": False, "method": "", "extracted_data": "", "metadata": {}}

    return result


def _run_exiftool(path: Path) -> Dict[str, str]:
    """Run exiftool to extract metadata. Returns empty dict if unavailable."""
    exiftool_bin = shutil.which("exiftool")
    if not exiftool_bin:
        # Fallback: basic metadata from file stats
        return _basic_metadata(path)

    try:
        proc = subprocess.run(
            [exiftool_bin, str(path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return _parse_exiftool_output(proc.stdout)
    except (subprocess.TimeoutExpired, OSError):
        pass

    return _basic_metadata(path)


def _parse_exiftool_output(output: str) -> Dict[str, str]:
    """Parse exiftool key-value output."""
    metadata: Dict[str, str] = {}
    for line in output.strip().split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            metadata[key.strip()] = value.strip()
    return metadata


def _basic_metadata(path: Path) -> Dict[str, str]:
    """Get basic file metadata without external tools."""
    try:
        stat = path.stat()
        return {
            "File Name": path.name,
            "File Size": f"{stat.st_size} bytes",
            "File Type": path.suffix.lstrip(".").upper() or "unknown",
        }
    except OSError:
        return {}


def _check_metadata_anomalies(metadata: Dict[str, str], path: Path) -> List[str]:
    """Check metadata for suspicious entries that might indicate hidden data."""
    anomalies: List[str] = []

    # Check for comments containing flag-like patterns
    flag_pattern = re.compile(r"(flag|ctf|key|secret|hidden)\{[^}]+\}", re.IGNORECASE)
    for key, value in metadata.items():
        if flag_pattern.search(value):
            anomalies.append(f"Flag-like pattern in {key}: {value}")
        # Check for unusually long or suspicious values
        if key.lower() in ("comment", "user comment", "description", "artist", "copyright"):
            if len(value) > 50 or any(c not in " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?-_()" for c in value):
                anomalies.append(f"Suspicious {key}: {value[:200]}")

    return anomalies


def _search_strings(path: Path, min_length: int = 6) -> str:
    """Search for flag-like strings in the image file."""
    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return ""

    # Extract printable strings
    strings: List[str] = []
    current: List[str] = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))

    # Search for flag patterns
    flag_pattern = re.compile(r"(flag|ctf|key|secret)\{[^}]+\}", re.IGNORECASE)
    for s in strings:
        match = flag_pattern.search(s)
        if match:
            return match.group(0)

    # Search for base64-encoded flags
    import base64
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for s in strings:
        for m in b64_pattern.finditer(s):
            try:
                decoded = base64.b64decode(m.group(0)).decode("utf-8", errors="ignore")
                if flag_pattern.search(decoded):
                    return f"base64_decoded: {decoded}"
            except Exception:
                continue

    return ""


def _run_steghide(path: Path) -> str:
    """Run steghide to extract hidden data. Works on JPEG/BMP."""
    steghide_bin = shutil.which("steghide")
    if not steghide_bin:
        return ""

    # Try extraction with empty passphrase
    try:
        proc = subprocess.run(
            [steghide_bin, "extract", "-sf", str(path), "-p", "", "-f", "-xf", "-"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Try info command
    try:
        proc = subprocess.run(
            [steghide_bin, "info", str(path), "-p", ""],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0 and "embedded" in proc.stdout.lower():
            return f"steghide_info: {proc.stdout.strip()}"
    except (subprocess.TimeoutExpired, OSError):
        pass

    return ""


def _run_zsteg(path: Path) -> str:
    """Run zsteg to detect LSB steganography in PNG/BMP."""
    zsteg_bin = shutil.which("zsteg")
    if not zsteg_bin:
        return ""

    try:
        proc = subprocess.run(
            [zsteg_bin, str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            # Filter for interesting results
            lines = proc.stdout.strip().split("\n")
            interesting: List[str] = []
            flag_pattern = re.compile(r"(flag|ctf|key|secret)\{[^}]+\}", re.IGNORECASE)
            for line in lines:
                if flag_pattern.search(line):
                    interesting.append(line.strip())
                elif "text:" in line.lower() and len(line) > 20:
                    interesting.append(line.strip())
            if interesting:
                return "; ".join(interesting[:5])
            # Return first few lines if no flags found
            return "; ".join(lines[:3])
    except (subprocess.TimeoutExpired, OSError):
        pass

    return ""


def _check_file_size_anomaly(path: Path) -> str:
    """Check if file size is anomalously large for its type."""
    try:
        data = path.read_bytes()
        file_size = len(data)
    except (OSError, IOError):
        return ""

    # Check PNG: find IEND and see if there's trailing data
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        iend_pos = data.find(b"IEND")
        if iend_pos != -1:
            end_of_png = iend_pos + 4 + 4  # type + CRC
            trailing = file_size - end_of_png
            if trailing > 10:
                return f"PNG has {trailing} bytes of trailing data after IEND"

    # Check JPEG: find EOI marker
    elif data[:2] == b"\xff\xd8":
        eoi_pos = data.rfind(b"\xff\xd9")
        if eoi_pos != -1:
            trailing = file_size - (eoi_pos + 2)
            if trailing > 10:
                return f"JPEG has {trailing} bytes of trailing data after EOI"

    return ""


@register
class StegoAnalyzeTool(BaseTool):
    """Analyze images for steganographic hidden data."""

    category = "ctf_misc"
    external_binary = "steghide"

    @property
    def name(self) -> str:
        return "stego_analyze"

    @property
    def description(self) -> str:
        return (
            "Analyze an image for hidden steganographic data using multiple methods: "
            "exiftool metadata analysis, string extraction, steghide, zsteg, and "
            "file size anomaly detection. Useful for CTF Misc/Stego challenges."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to the image file to analyze",
                },
                "method": {
                    "type": "string",
                    "enum": ["auto", "exiftool", "strings", "steghide", "zsteg"],
                    "description": "Analysis method (default: auto)",
                },
            },
            "required": ["image_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        image_path = kwargs.get("image_path", "")
        method = kwargs.get("method", "auto")

        result = stego_analyze(image_path, method)

        if "error" in result:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=result["error"],
                error=result["error"],
            )

        if result["hidden_data_found"]:
            summary = f"Hidden data found via {result['method']}: {result['extracted_data'][:100]}"
        else:
            summary = "No hidden data detected"

        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            parsed_data=result,
        )
