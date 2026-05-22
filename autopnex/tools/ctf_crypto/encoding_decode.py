"""Encoding detection and decoding tool for CTF challenges.

Supports: Base64, Base32, Hex, Morse code, URL encoding, ROT13, Binary.
Auto-detection mode identifies the encoding from the data pattern.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..base import BaseTool, ToolResult, register


# ---------------------------------------------------------------------------
# Morse code table
# ---------------------------------------------------------------------------
MORSE_TO_CHAR: Dict[str, str] = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    ".----.": "'", "-.-.--": "!", "-..-.": "/", "-.--.": "(",
    "-.--.-": ")", ".-...": "&", "---...": ":", "-.-.-.": ";",
    "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@", "...---...": "SOS",
}


def _decode_morse(data: str) -> Optional[str]:
    """Decode Morse code. Words separated by '  ' (double space) or '/'."""
    # Normalize: replace '/' with double space
    normalized = data.replace("/", "  ").strip()
    words = normalized.split("  ")
    result = []
    for word in words:
        chars = word.strip().split()
        decoded_word = ""
        for code in chars:
            ch = MORSE_TO_CHAR.get(code)
            if ch is None:
                return None  # Invalid Morse
            decoded_word += ch
        result.append(decoded_word)
    return " ".join(result)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _is_base64(data: str) -> bool:
    """Check if data looks like Base64."""
    stripped = data.strip()
    # Remove whitespace for check
    compact = re.sub(r"\s+", "", stripped)
    if not compact:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", compact)) and len(compact) % 4 == 0


def _is_base32(data: str) -> bool:
    """Check if data looks like Base32."""
    compact = re.sub(r"\s+", "", data.strip()).upper()
    if not compact:
        return False
    return bool(re.fullmatch(r"[A-Z2-7]+=*", compact)) and len(compact) % 8 == 0


def _is_hex(data: str) -> bool:
    """Check if data looks like hex (even length, only hex chars)."""
    compact = re.sub(r"[\s:]", "", data.strip())
    if not compact:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", compact)) and len(compact) % 2 == 0


def _is_morse(data: str) -> bool:
    """Check if data looks like Morse code."""
    stripped = data.strip()
    return bool(re.fullmatch(r"[.\- /]+", stripped)) and ("." in stripped or "-" in stripped)


def _is_binary(data: str) -> bool:
    """Check if data looks like binary (groups of 0s and 1s)."""
    stripped = data.strip()
    return bool(re.fullmatch(r"[01 ]+", stripped)) and " " in stripped


def _is_url_encoded(data: str) -> bool:
    """Check if data contains URL-encoded sequences."""
    return "%" in data and bool(re.search(r"%[0-9a-fA-F]{2}", data))


# ---------------------------------------------------------------------------
# Decode functions
# ---------------------------------------------------------------------------

def _try_base64(data: str) -> Optional[str]:
    try:
        compact = re.sub(r"\s+", "", data.strip())
        decoded = base64.b64decode(compact)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_base32(data: str) -> Optional[str]:
    try:
        compact = re.sub(r"\s+", "", data.strip()).upper()
        # Pad if needed
        padding = (8 - len(compact) % 8) % 8
        compact += "=" * padding
        decoded = base64.b32decode(compact)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_hex(data: str) -> Optional[str]:
    try:
        compact = re.sub(r"[\s:]", "", data.strip())
        decoded = bytes.fromhex(compact)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_morse(data: str) -> Optional[str]:
    return _decode_morse(data.strip())


def _try_url(data: str) -> Optional[str]:
    try:
        return urllib.parse.unquote(data)
    except Exception:
        return None


def _try_rot13(data: str) -> Optional[str]:
    return data.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def _try_binary(data: str) -> Optional[str]:
    try:
        groups = data.strip().split()
        chars = []
        for group in groups:
            if len(group) not in (7, 8):
                # Try treating the whole thing as one binary number
                val = int(data.replace(" ", ""), 2)
                length = (val.bit_length() + 7) // 8
                return val.to_bytes(length, "big").decode("utf-8", errors="replace")
            chars.append(chr(int(group, 2)))
        return "".join(chars)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

def _auto_detect(data: str) -> List[Tuple[str, str]]:
    """Return list of (encoding_name, decoded_value) for all detected encodings."""
    results = []

    if _is_morse(data):
        decoded = _try_morse(data)
        if decoded:
            results.append(("morse", decoded))

    if _is_binary(data):
        decoded = _try_binary(data)
        if decoded:
            results.append(("binary", decoded))

    if _is_hex(data):
        decoded = _try_hex(data)
        if decoded:
            results.append(("hex", decoded))

    if _is_base32(data):
        decoded = _try_base32(data)
        if decoded:
            results.append(("base32", decoded))

    if _is_base64(data):
        decoded = _try_base64(data)
        if decoded:
            results.append(("base64", decoded))

    if _is_url_encoded(data):
        decoded = _try_url(data)
        if decoded and decoded != data:
            results.append(("url", decoded))

    return results


# ---------------------------------------------------------------------------
# Chained decoding
# ---------------------------------------------------------------------------


def _try_chained_decode(data: str, max_depth: int = 5) -> List[Tuple[str, str, List[str]]]:
    """Attempt chained decoding (e.g., Base64 → Hex → ASCII).

    Returns list of (final_decoded, last_encoding, chain) tuples.
    """
    results: List[Tuple[str, str, List[str]]] = []

    def _recurse(current: str, chain: List[str], depth: int) -> None:
        if depth >= max_depth:
            return
        candidates = _auto_detect(current)
        for enc, decoded in candidates:
            if decoded == current:
                continue
            new_chain = chain + [enc]
            results.append((decoded, enc, list(new_chain)))
            # Try further decoding
            _recurse(decoded, new_chain, depth + 1)

    _recurse(data, [], 0)
    return results


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def encoding_decode(data: str, encoding: str = "auto") -> dict:
    """Encoding detection and decode function for CTF challenges.

    Args:
        data: The encoded data to decode.
        encoding: One of "base64", "base32", "hex", "url", "rot13", "morse",
                  "binary", "auto".

    Returns:
        dict with keys: decoded, encoding, confidence.
    """
    result: Dict[str, Any] = {
        "decoded": "",
        "encoding": "",
        "confidence": 0.0,
    }

    if not data:
        return result

    decode_map_fn = {
        "base64": (_try_base64, _is_base64),
        "base32": (_try_base32, _is_base32),
        "hex": (_try_hex, _is_hex),
        "morse": (_try_morse, _is_morse),
        "url": (_try_url, _is_url_encoded),
        "rot13": (_try_rot13, lambda _: True),
        "binary": (_try_binary, _is_binary),
    }

    if encoding != "auto":
        entry = decode_map_fn.get(encoding)
        if entry is None:
            return result
        fn, _ = entry
        decoded = fn(data)
        if decoded is not None:
            result["decoded"] = decoded
            result["encoding"] = encoding
            result["confidence"] = 1.0
        return result

    # Auto mode
    candidates = _auto_detect(data)
    if candidates:
        best_enc, best_decoded = candidates[0]
        # Confidence based on how many checks passed
        confidence = 0.9 if len(candidates) == 1 else 0.7
        result["decoded"] = best_decoded
        result["encoding"] = best_enc
        result["confidence"] = confidence

        # Try chained decoding for deeper results
        chained = _try_chained_decode(data, max_depth=3)
        if chained:
            # Find the deepest chain
            deepest = max(chained, key=lambda x: len(x[2]))
            if len(deepest[2]) > 1:
                result["chained"] = {
                    "final_decoded": deepest[0],
                    "chain": deepest[2],
                }

    return result


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------

@register
class EncodingDecodeTool(BaseTool):
    category = "ctf_crypto"

    @property
    def name(self) -> str:
        return "encoding_decode"

    @property
    def description(self) -> str:
        return (
            "Encoding detection and decoding tool for CTF challenges. "
            "Auto-detects and decodes Base64, Base32, Hex, Morse code, URL encoding, "
            "ROT13, and binary. Specify encoding or use auto mode."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "description": "The encoded data to decode.",
                },
                "encoding": {
                    "type": "string",
                    "enum": ["base64", "base32", "hex", "morse", "url", "rot13", "binary", "auto"],
                    "description": "Encoding type. Default: auto.",
                },
            },
            "required": ["data"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        data: str = kwargs.get("data", "")
        encoding: str = kwargs.get("encoding", "auto")

        if not data:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="data is required",
                error="missing_data",
            )

        decode_map = {
            "base64": _try_base64,
            "base32": _try_base32,
            "hex": _try_hex,
            "morse": _try_morse,
            "url": _try_url,
            "rot13": _try_rot13,
            "binary": _try_binary,
        }

        if encoding != "auto":
            fn = decode_map.get(encoding)
            if fn is None:
                return ToolResult(
                    success=False,
                    tool=self.name,
                    summary=f"Unknown encoding: {encoding}",
                    error="unknown_encoding",
                )
            decoded = fn(data)
            if decoded is None:
                return ToolResult(
                    success=False,
                    tool=self.name,
                    summary=f"Failed to decode as {encoding}",
                    error="decode_failed",
                    parsed_data={"encoding": encoding, "input": data},
                )
            return ToolResult(
                success=True,
                tool=self.name,
                summary=f"Decoded {encoding}: {decoded[:100]!r}",
                parsed_data={"encoding": encoding, "decoded": decoded, "input": data},
                raw_output=decoded,
            )

        # Auto mode
        candidates = _auto_detect(data)
        if not candidates:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="Could not detect encoding",
                error="detection_failed",
                parsed_data={"input": data, "candidates": []},
            )

        best_encoding, best_decoded = candidates[0]
        return ToolResult(
            success=True,
            tool=self.name,
            summary=f"Detected {best_encoding}: {best_decoded[:100]!r}",
            parsed_data={
                "encoding": best_encoding,
                "decoded": best_decoded,
                "input": data,
                "all_candidates": [
                    {"encoding": enc, "decoded": dec[:200]} for enc, dec in candidates
                ],
            },
            raw_output=best_decoded,
        )
