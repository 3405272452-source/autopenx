"""Flag 引擎属性测试 — 使用 hypothesis 进行 property-based testing。

验证 FlagEngine 的核心正确性属性：
1. Flag 提取完整性 (Extraction Completeness)
2. 编码往返 (Encoding Roundtrip)
3. 验证一致性 (Validation Consistency)
4. 去重保证 (Deduplication)
5. 置信度范围 (Confidence Range)
"""
from __future__ import annotations

import base64
import codecs
import urllib.parse

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from autopnex.ctf.flag_engine import FlagEngine


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Generate valid flag content: alphanumeric + underscore + dash, length 1-50
flag_content_strategy = st.text(
    alphabet=st.sampled_from(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789_-"
    ),
    min_size=1,
    max_size=50,
)

# Longer flag content for encoding roundtrip tests.
# The engine's _decode() uses minimum-length patterns for encoded fragments:
#   - base64 pattern requires >= 20 base64 chars (needs >= 15 bytes input, i.e. content >= 9 chars)
#   - hex pattern requires >= 20 hex chars (needs >= 10 bytes input, i.e. content >= 4 chars)
# We use min_size=10 to safely exceed both thresholds.
flag_content_for_encoding_strategy = st.text(
    alphabet=st.sampled_from(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789_-"
    ),
    min_size=10,
    max_size=50,
)

# Generate a complete flag string in standard format
flag_strategy = flag_content_strategy.map(lambda c: f"flag{{{c}}}")

# Generate arbitrary surrounding text (no braces to avoid accidental flag patterns)
surrounding_text_strategy = st.text(
    alphabet=st.sampled_from(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789 \t\n.,;:!?-_=+/\\@#$%^&*()"
    ),
    min_size=0,
    max_size=100,
)

# Repeat count for deduplication tests
repeat_count_strategy = st.integers(min_value=2, max_value=10)


# ---------------------------------------------------------------------------
# Property 1: Flag 提取完整性 (Extraction Completeness)
# ---------------------------------------------------------------------------

class TestExtractionCompleteness:
    """**Validates: Requirements 1.2**

    For any generated flag string matching the standard format `flag{...}`,
    when embedded in arbitrary text, `scan()` should find it.
    """

    @given(
        flag_content=flag_content_strategy,
        prefix=surrounding_text_strategy,
        suffix=surrounding_text_strategy,
    )
    @settings(max_examples=100)
    def test_scan_finds_embedded_flag(
        self, flag_content: str, prefix: str, suffix: str
    ) -> None:
        """scan() finds a standard-format flag embedded in arbitrary text."""
        flag = f"flag{{{flag_content}}}"
        text = f"{prefix}{flag}{suffix}"

        engine = FlagEngine()
        candidates = engine.scan(text)

        found_values = [c.value for c in candidates]
        assert flag in found_values, (
            f"scan() did not find flag '{flag}' in text"
        )


# ---------------------------------------------------------------------------
# Property 2: 编码往返 (Encoding Roundtrip)
# ---------------------------------------------------------------------------

class TestEncodingRoundtrip:
    """**Validates: Requirements 1.2**

    For any flag string, encoding it with base64/hex/rot13/url and then
    calling `decode_and_scan()` should recover the original flag.
    """

    @given(flag_content=flag_content_for_encoding_strategy)
    @settings(max_examples=100)
    def test_base64_roundtrip(self, flag_content: str) -> None:
        """Base64 encode then decode_and_scan recovers the flag."""
        flag = f"flag{{{flag_content}}}"
        encoded = base64.b64encode(flag.encode("utf-8")).decode("ascii")

        engine = FlagEngine()
        candidates = engine.decode_and_scan(encoded)

        found_values = [c.value for c in candidates]
        assert flag in found_values, (
            f"decode_and_scan(base64) did not recover flag '{flag}'"
        )

    @given(flag_content=flag_content_for_encoding_strategy)
    @settings(max_examples=100)
    def test_hex_roundtrip(self, flag_content: str) -> None:
        """Hex encode then decode_and_scan recovers the flag."""
        flag = f"flag{{{flag_content}}}"
        encoded = flag.encode("utf-8").hex()

        engine = FlagEngine()
        candidates = engine.decode_and_scan(encoded)

        found_values = [c.value for c in candidates]
        assert flag in found_values, (
            f"decode_and_scan(hex) did not recover flag '{flag}'"
        )

    @given(flag_content=flag_content_strategy)
    @settings(max_examples=100)
    def test_rot13_roundtrip(self, flag_content: str) -> None:
        """ROT13 encode then decode_and_scan recovers the flag."""
        flag = f"flag{{{flag_content}}}"
        encoded = codecs.encode(flag, "rot_13")

        engine = FlagEngine()
        candidates = engine.decode_and_scan(encoded)

        found_values = [c.value for c in candidates]
        assert flag in found_values, (
            f"decode_and_scan(rot13) did not recover flag '{flag}'"
        )

    @given(flag_content=flag_content_strategy)
    @settings(max_examples=100)
    def test_url_roundtrip(self, flag_content: str) -> None:
        """URL encode then decode_and_scan recovers the flag."""
        flag = f"flag{{{flag_content}}}"
        encoded = urllib.parse.quote(flag, safe="")

        engine = FlagEngine()
        candidates = engine.decode_and_scan(encoded)

        found_values = [c.value for c in candidates]
        assert flag in found_values, (
            f"decode_and_scan(url) did not recover flag '{flag}'"
        )


# ---------------------------------------------------------------------------
# Property 3: 验证一致性 (Validation Consistency)
# ---------------------------------------------------------------------------

class TestValidationConsistency:
    """**Validates: Requirements 1.2**

    For any flag found by `scan()`, `validate()` with the matching
    standard format should return True.
    """

    @given(
        flag_content=flag_content_strategy,
        prefix=surrounding_text_strategy,
        suffix=surrounding_text_strategy,
    )
    @settings(max_examples=100)
    def test_scanned_flags_validate(
        self, flag_content: str, prefix: str, suffix: str
    ) -> None:
        """Every flag found by scan() validates against the standard format."""
        flag = f"flag{{{flag_content}}}"
        text = f"{prefix}{flag}{suffix}"

        engine = FlagEngine()
        candidates = engine.scan(text)

        # The standard format regex from DEFAULT_FORMATS
        standard_format = r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?]+\}"

        # Find the candidate matching our generated flag
        matching = [c for c in candidates if c.value == flag]
        assert len(matching) > 0, f"Flag '{flag}' not found by scan()"

        for candidate in matching:
            assert engine.validate(candidate.value, standard_format), (
                f"validate() returned False for scanned flag '{candidate.value}'"
            )


# ---------------------------------------------------------------------------
# Property 4: 去重保证 (Deduplication)
# ---------------------------------------------------------------------------

class TestDeduplication:
    """**Validates: Requirements 1.2**

    For any text containing the same flag N times, scan() returns it
    exactly once.
    """

    @given(
        flag_content=flag_content_strategy,
        n=repeat_count_strategy,
    )
    @settings(max_examples=100)
    def test_duplicate_flags_deduplicated(
        self, flag_content: str, n: int
    ) -> None:
        """scan() returns a duplicated flag exactly once."""
        flag = f"flag{{{flag_content}}}"
        # Repeat the flag N times separated by spaces
        text = " ".join([flag] * n)

        engine = FlagEngine()
        candidates = engine.scan(text)

        # Count how many candidates have this exact flag value
        matching = [c for c in candidates if c.value == flag]
        assert len(matching) == 1, (
            f"Expected exactly 1 candidate for flag '{flag}' repeated {n} times, "
            f"got {len(matching)}"
        )


# ---------------------------------------------------------------------------
# Property 5: 置信度范围 (Confidence Range)
# ---------------------------------------------------------------------------

class TestConfidenceRange:
    """**Validates: Requirements 1.2**

    All candidates returned by scan() and decode_and_scan() have
    confidence in [0.0, 1.0].
    """

    @given(
        flag_content=flag_content_strategy,
        prefix=surrounding_text_strategy,
        suffix=surrounding_text_strategy,
    )
    @settings(max_examples=100)
    def test_scan_confidence_in_range(
        self, flag_content: str, prefix: str, suffix: str
    ) -> None:
        """All candidates from scan() have confidence in [0.0, 1.0]."""
        flag = f"flag{{{flag_content}}}"
        text = f"{prefix}{flag}{suffix}"

        engine = FlagEngine()
        candidates = engine.scan(text)

        for candidate in candidates:
            assert 0.0 <= candidate.confidence <= 1.0, (
                f"Confidence {candidate.confidence} out of range for "
                f"candidate '{candidate.value}'"
            )

    @given(flag_content=flag_content_strategy)
    @settings(max_examples=50)
    def test_decode_and_scan_confidence_in_range(
        self, flag_content: str
    ) -> None:
        """All candidates from decode_and_scan() have confidence in [0.0, 1.0]."""
        flag = f"flag{{{flag_content}}}"
        encoded = base64.b64encode(flag.encode("utf-8")).decode("ascii")

        engine = FlagEngine()
        candidates = engine.decode_and_scan(encoded)

        for candidate in candidates:
            assert 0.0 <= candidate.confidence <= 1.0, (
                f"Confidence {candidate.confidence} out of range for "
                f"candidate '{candidate.value}'"
            )
