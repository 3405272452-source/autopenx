"""Classical cipher analysis tool for CTF challenges.

Implements:
- Caesar cipher (brute-force all 26 shifts, scored by English frequency)
- ROT13
- Vigenere cipher (decrypt with key, or Kasiski analysis for key discovery)
- Auto mode: tries all ciphers
"""
from __future__ import annotations

import re
import string
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from ..base import BaseTool, ToolResult, register


# ---------------------------------------------------------------------------
# English letter frequency table (approximate)
# ---------------------------------------------------------------------------
ENGLISH_FREQ: Dict[str, float] = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}

ENGLISH_COMMON_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
    "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
    "but", "his", "by", "from", "they", "we", "say", "her", "she", "or",
    "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "is", "are", "was", "were", "has", "had", "been", "can", "could",
}


def _score_english(text: str) -> float:
    """Score text by English letter frequency (higher = more English-like)."""
    text_lower = text.lower()
    letters = [c for c in text_lower if c.isalpha()]
    if not letters:
        return 0.0

    # Frequency score
    counts = Counter(letters)
    total = len(letters)
    freq_score = sum(
        counts.get(ch, 0) / total * ENGLISH_FREQ.get(ch, 0)
        for ch in string.ascii_lowercase
    )

    # Bonus for common English words
    words = re.findall(r"[a-z]+", text_lower)
    word_bonus = sum(1.0 for w in words if w in ENGLISH_COMMON_WORDS)

    return freq_score + word_bonus * 0.5


# ---------------------------------------------------------------------------
# Caesar cipher
# ---------------------------------------------------------------------------

def _caesar_shift(text: str, shift: int) -> str:
    """Apply a Caesar shift to text."""
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        elif ch.islower():
            result.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        else:
            result.append(ch)
    return "".join(result)


def _caesar_attack(ciphertext: str) -> Dict[str, Any]:
    """Try all 26 Caesar shifts and return the best one."""
    best_shift = 0
    best_score = -1.0
    best_text = ciphertext

    for shift in range(26):
        candidate = _caesar_shift(ciphertext, shift)
        score = _score_english(candidate)
        if score > best_score:
            best_score = score
            best_shift = shift
            best_text = candidate

    return {
        "success": True,
        "cipher": "caesar",
        "key": str(best_shift),
        "plaintext": best_text,
        "score": best_score,
        "all_shifts": [
            {"shift": s, "text": _caesar_shift(ciphertext, s)[:60]}
            for s in range(26)
        ],
    }


# ---------------------------------------------------------------------------
# ROT13
# ---------------------------------------------------------------------------

def _rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def _rot13_attack(ciphertext: str) -> Dict[str, Any]:
    plaintext = _rot13(ciphertext)
    return {
        "success": True,
        "cipher": "rot13",
        "key": "13",
        "plaintext": plaintext,
    }


# ---------------------------------------------------------------------------
# Vigenere cipher
# ---------------------------------------------------------------------------

def _vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Vigenere ciphertext with given key."""
    key_lower = key.lower()
    key_len = len(key_lower)
    if key_len == 0:
        return ciphertext

    result = []
    key_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(key_lower[key_idx % key_len]) - ord("a")
            if ch.isupper():
                result.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
            else:
                result.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def _kasiski_key_length(ciphertext: str, max_key_len: int = 20) -> List[int]:
    """Estimate Vigenere key length using Index of Coincidence."""
    letters = [c.lower() for c in ciphertext if c.isalpha()]
    if len(letters) < 20:
        return [1]

    scores = []
    for key_len in range(1, min(max_key_len + 1, len(letters) // 2)):
        # Split into key_len streams and compute average IC
        ic_sum = 0.0
        for i in range(key_len):
            stream = letters[i::key_len]
            n = len(stream)
            if n < 2:
                ic_sum += 0
                continue
            counts = Counter(stream)
            ic = sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))
            ic_sum += ic
        avg_ic = ic_sum / key_len
        scores.append((key_len, avg_ic))

    # English IC ≈ 0.065; random ≈ 0.038
    scores.sort(key=lambda x: abs(x[1] - 0.065))
    return [s[0] for s in scores[:3]]


def _crack_vigenere_key(ciphertext: str, key_len: int) -> str:
    """Crack Vigenere key of given length using frequency analysis."""
    letters = [c.lower() for c in ciphertext if c.isalpha()]
    key = []
    for i in range(key_len):
        stream = letters[i::key_len]
        # Find shift that maximizes correlation with English frequency
        best_shift = 0
        best_score = -1.0
        for shift in range(26):
            score = 0.0
            for ch in stream:
                shifted = chr((ord(ch) - ord("a") - shift) % 26 + ord("a"))
                score += ENGLISH_FREQ.get(shifted, 0)
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord("a")))
    return "".join(key)


def _vigenere_attack(ciphertext: str, key: str = "") -> Dict[str, Any]:
    """Decrypt Vigenere cipher. If key not provided, attempt Kasiski analysis."""
    if key:
        plaintext = _vigenere_decrypt(ciphertext, key)
        return {
            "success": True,
            "cipher": "vigenere",
            "key": key,
            "plaintext": plaintext,
        }

    # Auto key discovery
    key_lengths = _kasiski_key_length(ciphertext)
    best_result = None
    best_score = -1.0

    for kl in key_lengths:
        candidate_key = _crack_vigenere_key(ciphertext, kl)
        plaintext = _vigenere_decrypt(ciphertext, candidate_key)
        score = _score_english(plaintext)
        if score > best_score:
            best_score = score
            best_result = {
                "success": True,
                "cipher": "vigenere",
                "key": candidate_key,
                "plaintext": plaintext,
                "score": score,
                "key_length": kl,
            }

    if best_result:
        return best_result

    return {"success": False, "reason": "Could not determine Vigenere key"}


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def classical_cipher(ciphertext: str, cipher_type: str = "auto") -> dict:
    """Classical cipher analysis function for CTF challenges.

    Args:
        ciphertext: The ciphertext to analyze/decrypt.
        cipher_type: One of "caesar", "vigenere", "rot13", "auto".

    Returns:
        dict with keys: success, plaintext, method, key.
    """
    result: Dict[str, Any] = {
        "success": False,
        "plaintext": "",
        "method": "",
        "key": "",
    }

    if not ciphertext:
        return result

    if cipher_type == "caesar":
        res = _caesar_attack(ciphertext)
    elif cipher_type == "rot13":
        res = _rot13_attack(ciphertext)
    elif cipher_type == "vigenere":
        res = _vigenere_attack(ciphertext)
    else:  # auto
        candidates = []
        for name, fn, args in [
            ("rot13", _rot13_attack, (ciphertext,)),
            ("caesar", _caesar_attack, (ciphertext,)),
            ("vigenere", _vigenere_attack, (ciphertext, "")),
        ]:
            res = fn(*args)
            if res.get("success"):
                score = res.get("score", _score_english(res.get("plaintext", "")))
                candidates.append((score, name, res))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            _, _, res = candidates[0]
        else:
            return result

    if res.get("success"):
        result["success"] = True
        result["plaintext"] = res.get("plaintext", "")
        result["method"] = res.get("cipher", cipher_type)
        result["key"] = res.get("key", "")

    return result


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------


@register
class ClassicalCipherTool(BaseTool):
    category = "ctf_crypto"

    @property
    def name(self) -> str:
        return "classical_cipher"

    @property
    def description(self) -> str:
        return (
            "Classical cipher analysis tool for CTF challenges. "
            "Supports Caesar (brute-force), ROT13, Vigenere (with or without key), "
            "and auto mode. Returns decrypted text and key used."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "ciphertext": {
                    "type": "string",
                    "description": "The ciphertext to analyze/decrypt.",
                },
                "cipher": {
                    "type": "string",
                    "enum": ["caesar", "vigenere", "rot13", "auto"],
                    "description": "Cipher type. Default: auto.",
                },
                "key": {
                    "type": "string",
                    "description": "Key for Vigenere decryption (optional).",
                },
            },
            "required": ["ciphertext"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        ciphertext: str = kwargs.get("ciphertext", "")
        cipher: str = kwargs.get("cipher", "auto")
        key: str = kwargs.get("key", "")

        if not ciphertext:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="ciphertext is required",
                error="missing_ciphertext",
            )

        results: Dict[str, Any] = {}

        if cipher == "caesar":
            results = _caesar_attack(ciphertext)
        elif cipher == "rot13":
            results = _rot13_attack(ciphertext)
        elif cipher == "vigenere":
            results = _vigenere_attack(ciphertext, key)
        else:  # auto
            candidates = []
            for name, fn, args in [
                ("rot13", _rot13_attack, (ciphertext,)),
                ("caesar", _caesar_attack, (ciphertext,)),
                ("vigenere", _vigenere_attack, (ciphertext, key)),
            ]:
                res = fn(*args)
                if res.get("success"):
                    score = res.get("score", _score_english(res.get("plaintext", "")))
                    candidates.append((score, name, res))

            if candidates:
                candidates.sort(key=lambda x: x[0], reverse=True)
                best_score, best_name, best_res = candidates[0]
                results = best_res
                results["all_attempts"] = {
                    c[1]: {"key": c[2].get("key"), "plaintext": c[2].get("plaintext", "")[:80]}
                    for c in candidates
                }
            else:
                results = {"success": False, "reason": "No cipher attack succeeded"}

        success = results.get("success", False)
        plaintext = results.get("plaintext", "")
        used_key = results.get("key", "")
        summary = (
            f"Cipher: {results.get('cipher', cipher)}, Key: {used_key!r}, "
            f"Plaintext: {plaintext[:100]!r}"
            if success
            else f"Failed: {results.get('reason', 'unknown')}"
        )

        return ToolResult(
            success=success,
            tool=self.name,
            summary=summary,
            parsed_data=results,
            raw_output=plaintext,
        )
