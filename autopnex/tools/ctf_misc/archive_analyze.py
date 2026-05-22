"""Archive analysis tool: analyze ZIP files, detect pseudo-encryption, extract contents.

Provides both a standalone function ``archive_analyze(archive_path, method)`` and a
registered ``ArchiveAnalyzeTool`` class for use in the tool registry.
"""
from __future__ import annotations

import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register


def archive_analyze(archive_path: str, method: str = "auto") -> dict:
    """Analyze an archive file (ZIP) for contents, encryption, and pseudo-encryption.

    Args:
        archive_path: Path to the archive file.
        method: Analysis method - "auto", "list", "pseudo_encrypt", "extract".

    Returns:
        Dictionary with keys: file_list, encrypted, pseudo_encrypted, extracted.
        On error, includes an 'error' key.
    """
    if not archive_path:
        return {"error": "archive_path is required", "file_list": [], "encrypted": False, "pseudo_encrypted": False, "extracted": []}

    path = Path(archive_path)
    if not path.exists():
        return {"error": f"File not found: {archive_path}", "file_list": [], "encrypted": False, "pseudo_encrypted": False, "extracted": []}

    result: Dict[str, Any] = {
        "file_list": [],
        "encrypted": False,
        "pseudo_encrypted": False,
        "extracted": [],
    }

    if method == "auto":
        # Run all analyses
        result["file_list"] = _list_contents(path)
        result["encrypted"] = _check_encrypted(path)
        result["pseudo_encrypted"] = _check_pseudo_encrypted(path)
        if not result["encrypted"] or result["pseudo_encrypted"]:
            result["extracted"] = _attempt_extraction(path, result["pseudo_encrypted"])
    elif method == "list":
        result["file_list"] = _list_contents(path)
    elif method == "pseudo_encrypt":
        result["file_list"] = _list_contents(path)
        result["encrypted"] = _check_encrypted(path)
        result["pseudo_encrypted"] = _check_pseudo_encrypted(path)
    elif method == "extract":
        result["file_list"] = _list_contents(path)
        result["encrypted"] = _check_encrypted(path)
        result["pseudo_encrypted"] = _check_pseudo_encrypted(path)
        result["extracted"] = _attempt_extraction(path, result["pseudo_encrypted"])
    else:
        return {"error": f"Unknown method: {method}", "file_list": [], "encrypted": False, "pseudo_encrypted": False, "extracted": []}

    return result


def _list_contents(path: Path) -> List[str]:
    """List contents of a ZIP archive."""
    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            entries: List[str] = []
            for info in zf.infolist():
                size_str = f" ({info.file_size} bytes)" if info.file_size > 0 else ""
                compress_str = ""
                if info.compress_type == zipfile.ZIP_DEFLATED:
                    compress_str = " [deflated]"
                elif info.compress_type == zipfile.ZIP_STORED:
                    compress_str = " [stored]"
                encrypted_str = " [encrypted]" if info.flag_bits & 0x1 else ""
                entries.append(f"{info.filename}{size_str}{compress_str}{encrypted_str}")
            return entries
    except zipfile.BadZipFile:
        return ["error: not a valid ZIP file"]
    except Exception as e:
        return [f"error: {str(e)}"]


def _check_encrypted(path: Path) -> bool:
    """Check if any file in the ZIP is encrypted."""
    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # Encryption bit set
                    return True
    except (zipfile.BadZipFile, Exception):
        pass
    return False


def _check_pseudo_encrypted(path: Path) -> bool:
    """Detect ZIP pseudo-encryption by comparing local and central directory flags.

    In pseudo-encryption, the encryption flag (bit 0) is set in the central
    directory header but the file is not actually encrypted. This can be detected
    by checking if the local file header has a different flag value, or by
    attempting to read the file without a password.
    """
    try:
        data = path.read_bytes()
    except (OSError, IOError):
        return False

    # Find local file headers and central directory headers
    local_flags: Dict[str, int] = {}
    central_flags: Dict[str, int] = {}

    # Parse local file headers (PK\x03\x04)
    offset = 0
    while offset < len(data) - 30:
        if data[offset:offset + 4] == b"PK\x03\x04":
            try:
                flags = struct.unpack_from("<H", data, offset + 6)[0]
                fname_len = struct.unpack_from("<H", data, offset + 26)[0]
                extra_len = struct.unpack_from("<H", data, offset + 28)[0]
                if offset + 30 + fname_len <= len(data):
                    fname = data[offset + 30:offset + 30 + fname_len].decode("utf-8", errors="replace")
                    local_flags[fname] = flags
                offset += 30 + fname_len + extra_len
            except (struct.error, UnicodeDecodeError):
                offset += 4
        else:
            offset += 1
            # Skip ahead to find next signature
            next_pk = data.find(b"PK", offset)
            if next_pk == -1:
                break
            offset = next_pk

    # Parse central directory headers (PK\x01\x02)
    offset = 0
    while offset < len(data) - 46:
        if data[offset:offset + 4] == b"PK\x01\x02":
            try:
                flags = struct.unpack_from("<H", data, offset + 8)[0]
                fname_len = struct.unpack_from("<H", data, offset + 28)[0]
                extra_len = struct.unpack_from("<H", data, offset + 30)[0]
                comment_len = struct.unpack_from("<H", data, offset + 32)[0]
                if offset + 46 + fname_len <= len(data):
                    fname = data[offset + 46:offset + 46 + fname_len].decode("utf-8", errors="replace")
                    central_flags[fname] = flags
                offset += 46 + fname_len + extra_len + comment_len
            except (struct.error, UnicodeDecodeError):
                offset += 4
        else:
            offset += 1
            next_pk = data.find(b"PK", offset)
            if next_pk == -1:
                break
            offset = next_pk

    # Compare flags: pseudo-encryption if central says encrypted but local doesn't
    for fname in central_flags:
        central_encrypted = bool(central_flags[fname] & 0x1)
        local_encrypted = bool(local_flags.get(fname, 0) & 0x1)
        if central_encrypted and not local_encrypted:
            return True

    # Alternative check: if encrypted flag is set but we can still read the data
    if _check_encrypted(path):
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1 and not info.is_dir():
                        # Try reading without password - if it works, it's pseudo-encrypted
                        try:
                            zf.read(info.filename)
                            return True
                        except RuntimeError:
                            # Genuinely encrypted
                            pass
                        except Exception:
                            pass
                        break
        except (zipfile.BadZipFile, Exception):
            pass

    return False


def _attempt_extraction(path: Path, is_pseudo_encrypted: bool) -> List[str]:
    """Attempt to extract files from the archive."""
    extracted: List[str] = []

    if is_pseudo_encrypted:
        # For pseudo-encrypted ZIPs, patch the flags and extract
        extracted = _extract_pseudo_encrypted(path)
    else:
        # Normal extraction
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                with tempfile.TemporaryDirectory():
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        if info.flag_bits & 0x1:
                            # Try common passwords
                            passwords = [b"", b"password", b"123456", b"admin", b"flag"]
                            for pwd in passwords:
                                try:
                                    content = zf.read(info.filename, pwd=pwd)
                                    preview = content[:200].decode("utf-8", errors="replace")
                                    extracted.append(f"{info.filename}: {preview}")
                                    break
                                except (RuntimeError, Exception):
                                    continue
                        else:
                            try:
                                content = zf.read(info.filename)
                                preview = content[:200].decode("utf-8", errors="replace")
                                extracted.append(f"{info.filename}: {preview}")
                            except Exception:
                                extracted.append(f"{info.filename}: [extraction failed]")
        except (zipfile.BadZipFile, Exception) as e:
            extracted.append(f"error: {str(e)}")

    return extracted


def _extract_pseudo_encrypted(path: Path) -> List[str]:
    """Extract files from a pseudo-encrypted ZIP by clearing encryption flags."""
    extracted: List[str] = []

    try:
        data = bytearray(path.read_bytes())
    except (OSError, IOError):
        return ["error: failed to read file"]

    # Clear encryption bit in local file headers
    offset = 0
    while offset < len(data) - 30:
        if data[offset:offset + 4] == b"PK\x03\x04":
            # Clear bit 0 of general purpose bit flag
            flags = struct.unpack_from("<H", data, offset + 6)[0]
            flags &= ~0x1  # Clear encryption bit
            struct.pack_into("<H", data, offset + 6, flags)
            fname_len = struct.unpack_from("<H", data, offset + 26)[0]
            extra_len = struct.unpack_from("<H", data, offset + 28)[0]
            comp_size = struct.unpack_from("<I", data, offset + 18)[0]
            offset += 30 + fname_len + extra_len + comp_size
        else:
            offset += 1
            next_pk = data.find(b"PK", offset)
            if next_pk == -1:
                break
            offset = next_pk

    # Clear encryption bit in central directory headers
    offset = 0
    while offset < len(data) - 46:
        if data[offset:offset + 4] == b"PK\x01\x02":
            flags = struct.unpack_from("<H", data, offset + 8)[0]
            flags &= ~0x1
            struct.pack_into("<H", data, offset + 8, flags)
            fname_len = struct.unpack_from("<H", data, offset + 28)[0]
            extra_len = struct.unpack_from("<H", data, offset + 30)[0]
            comment_len = struct.unpack_from("<H", data, offset + 32)[0]
            offset += 46 + fname_len + extra_len + comment_len
        else:
            offset += 1
            next_pk = data.find(b"PK", offset)
            if next_pk == -1:
                break
            offset = next_pk

    # Write patched ZIP to temp file and extract
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(bytes(data))
            tmp_path = tmp.name

        with zipfile.ZipFile(tmp_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    content = zf.read(info.filename)
                    preview = content[:200].decode("utf-8", errors="replace")
                    extracted.append(f"{info.filename}: {preview}")
                except Exception:
                    extracted.append(f"{info.filename}: [extraction failed]")

        Path(tmp_path).unlink(missing_ok=True)
    except Exception as e:
        extracted.append(f"error: {str(e)}")

    return extracted


@register
class ArchiveAnalyzeTool(BaseTool):
    """Analyze archive files (ZIP) for contents and pseudo-encryption."""

    category = "ctf_misc"

    @property
    def name(self) -> str:
        return "archive_analyze"

    @property
    def description(self) -> str:
        return (
            "Analyze ZIP archive files: list contents, detect real vs pseudo-encryption "
            "(ZIP flag manipulation), and attempt extraction. Useful for CTF Misc "
            "challenges involving archive forensics."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "archive_path": {
                    "type": "string",
                    "description": "Path to the ZIP archive file to analyze",
                },
                "method": {
                    "type": "string",
                    "enum": ["auto", "list", "pseudo_encrypt", "extract"],
                    "description": "Analysis method (default: auto)",
                },
            },
            "required": ["archive_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        archive_path = kwargs.get("archive_path", "")
        method = kwargs.get("method", "auto")

        result = archive_analyze(archive_path, method)

        if "error" in result:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=result["error"],
                error=result["error"],
            )

        summary_parts = [f"Files: {len(result['file_list'])}"]
        if result["encrypted"]:
            summary_parts.append("Encrypted: Yes")
        if result["pseudo_encrypted"]:
            summary_parts.append("PSEUDO-ENCRYPTED (can bypass!)")
        if result["extracted"]:
            summary_parts.append(f"Extracted: {len(result['extracted'])} items")

        return ToolResult(
            success=True,
            tool=self.name,
            summary=" | ".join(summary_parts),
            parsed_data=result,
        )
