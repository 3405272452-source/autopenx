"""Comprehensive unit tests for FlagEngine class.

Covers all scan formats, encoding/decoding, binary scanning,
validation, dynamic format registration, and internal _decode helper.
"""
from __future__ import annotations

import base64
import codecs
import urllib.parse

import pytest

from autopnex.ctf.flag_engine import FlagEngine
from autopnex.ctf.models import FlagCandidate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> FlagEngine:
    """Return a default FlagEngine instance."""
    return FlagEngine()


# ===========================================================================
# 1. scan() tests
# ===========================================================================


class TestScan:
    """Tests for FlagEngine.scan() method."""

    def test_standard_flag_format(self, engine: FlagEngine):
        """Detect standard flag{...} format."""
        text = "The answer is flag{hello_world_123}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "flag{hello_world_123}" in values

    def test_ctf_prefix_format(self, engine: FlagEngine):
        """Detect CTF{...} format."""
        text = "Submit CTF{upper_case_flag} to score"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "CTF{upper_case_flag}" in values

    def test_hctf_format(self, engine: FlagEngine):
        """Detect hctf{...} platform-specific format."""
        text = "Flag: hctf{platform_specific_flag}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "hctf{platform_specific_flag}" in values

    def test_sctf_format(self, engine: FlagEngine):
        """Detect sctf{...} platform-specific format."""
        text = "Answer: sctf{another_platform}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "sctf{another_platform}" in values

    def test_hitcon_format(self, engine: FlagEngine):
        """Detect hitcon{...} platform-specific format."""
        text = "hitcon{taiwan_ctf_2024}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "hitcon{taiwan_ctf_2024}" in values

    def test_bctf_format(self, engine: FlagEngine):
        """Detect bctf{...} platform-specific format."""
        text = "bctf{baidu_ctf_flag}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "bctf{baidu_ctf_flag}" in values

    def test_generic_brace_format_lower_confidence(self, engine: FlagEngine):
        """Generic brace format detected with lower confidence (0.6)."""
        text = "myctf{some_value}"
        candidates = engine.scan(text)
        # generic_brace should match this
        matching = [c for c in candidates if c.value == "myctf{some_value}"]
        assert len(matching) >= 1
        # Confidence should be lower than standard formats
        assert matching[0].confidence <= 0.6

    def test_md5_hash_detection(self, engine: FlagEngine):
        """Detect MD5 hash with lower confidence (0.5)."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"Hash: {md5}"
        candidates = engine.scan(text)
        matching = [c for c in candidates if c.value == md5]
        assert len(matching) == 1
        assert matching[0].confidence == 0.5

    def test_sha256_hash_detection(self, engine: FlagEngine):
        """Detect SHA256 hash with confidence 0.5."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"SHA256: {sha256}"
        candidates = engine.scan(text)
        matching = [c for c in candidates if c.value == sha256]
        assert len(matching) == 1
        assert matching[0].confidence == 0.5

    def test_uuid_flag_format(self, engine: FlagEngine):
        """Detect UUID-style flag format."""
        uuid_flag = "flag-deadbeef-1234-5678-9abc-def012345678"
        text = f"Your flag is: {uuid_flag}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert uuid_flag in values

    def test_multiple_flags_in_one_text(self, engine: FlagEngine):
        """Detect multiple different flags in the same text."""
        text = "First: flag{first_flag} and second: CTF{second_flag}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "flag{first_flag}" in values
        assert "CTF{second_flag}" in values

    def test_deduplication(self, engine: FlagEngine):
        """Same flag appearing twice should only appear once in results."""
        text = "flag{duplicate} some text flag{duplicate}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert values.count("flag{duplicate}") == 1

    def test_empty_content_returns_empty_list(self, engine: FlagEngine):
        """Empty content should return an empty list."""
        candidates = engine.scan("")
        assert candidates == []

    def test_confidence_ordering(self, engine: FlagEngine):
        """Results should be ordered by confidence descending."""
        # Include a standard flag (high confidence) and a generic brace (lower)
        text = "flag{high_conf} and myctf{low_conf}"
        candidates = engine.scan(text)
        # Verify descending order
        for i in range(len(candidates) - 1):
            assert candidates[i].confidence >= candidates[i + 1].confidence

    def test_context_extraction(self, engine: FlagEngine):
        """Context should include up to 50 chars before and after the match."""
        prefix = "A" * 60
        suffix = "B" * 60
        text = f"{prefix}flag{{test_context}}{suffix}"
        candidates = engine.scan(text)
        matching = [c for c in candidates if c.value == "flag{test_context}"]
        assert len(matching) == 1
        ctx = matching[0].context
        # Context should contain part of prefix and suffix
        assert "flag{test_context}" in ctx
        # Should be trimmed (not the full 60 chars of prefix/suffix)
        assert len(ctx) < len(text)

    def test_source_is_text_scan(self, engine: FlagEngine):
        """Source field should be 'text_scan' for scan() results."""
        text = "flag{source_check}"
        candidates = engine.scan(text)
        assert candidates[0].source == "text_scan"

    def test_encoding_is_plaintext(self, engine: FlagEngine):
        """Encoding field should be 'plaintext' for scan() results."""
        text = "flag{encoding_check}"
        candidates = engine.scan(text)
        assert candidates[0].encoding == "plaintext"

    def test_no_match_returns_empty(self, engine: FlagEngine):
        """Text with no flags should return empty list."""
        text = "This is just normal text with no flags at all."
        candidates = engine.scan(text)
        assert candidates == []


# ===========================================================================
# 2. decode_and_scan() tests
# ===========================================================================


class TestDecodeAndScan:
    """Tests for FlagEngine.decode_and_scan() method."""

    def test_base64_encoded_flag(self, engine: FlagEngine):
        """Detect flag encoded in Base64."""
        flag = "flag{base64_decoded}"
        encoded = base64.b64encode(flag.encode()).decode()
        candidates = engine.decode_and_scan(encoded)
        values = [c.value for c in candidates]
        assert "flag{base64_decoded}" in values

    def test_hex_encoded_flag(self, engine: FlagEngine):
        """Detect flag encoded in hex."""
        flag = "flag{hex_decoded_flag}"
        encoded = flag.encode().hex()
        candidates = engine.decode_and_scan(encoded)
        values = [c.value for c in candidates]
        assert "flag{hex_decoded_flag}" in values

    def test_rot13_encoded_flag(self, engine: FlagEngine):
        """Detect flag encoded in ROT13."""
        flag = "flag{rot13_test}"
        encoded = codecs.encode(flag, "rot_13")
        candidates = engine.decode_and_scan(encoded)
        values = [c.value for c in candidates]
        assert "flag{rot13_test}" in values

    def test_url_encoded_flag(self, engine: FlagEngine):
        """Detect flag encoded with URL encoding."""
        flag = "flag{url_encoded}"
        encoded = urllib.parse.quote(flag)
        candidates = engine.decode_and_scan(encoded)
        values = [c.value for c in candidates]
        assert "flag{url_encoded}" in values

    def test_confidence_multiplied_by_0_9(self, engine: FlagEngine):
        """Decoded flags should have confidence multiplied by 0.9."""
        flag = "flag{confidence_test}"
        encoded = base64.b64encode(flag.encode()).decode()
        candidates = engine.decode_and_scan(encoded)
        matching = [c for c in candidates if c.value == "flag{confidence_test}"]
        assert len(matching) >= 1
        # Standard flag confidence is 1.0, after 0.9 multiplier = 0.9
        assert matching[0].confidence == pytest.approx(0.9, abs=0.01)

    def test_encoding_field_set_correctly(self, engine: FlagEngine):
        """Encoding field should reflect the decoding method used."""
        flag = "flag{encoding_field}"
        encoded = base64.b64encode(flag.encode()).decode()
        candidates = engine.decode_and_scan(encoded)
        matching = [c for c in candidates if c.value == "flag{encoding_field}"]
        assert len(matching) >= 1
        assert matching[0].encoding == "base64"

    def test_invalid_encoding_content_handled_gracefully(self, engine: FlagEngine):
        """Invalid content for encoding should not raise, returns empty or skips."""
        # Content that is not valid base64/hex/etc.
        text = "!!!not_any_encoding!!!"
        # Should not raise
        candidates = engine.decode_and_scan(text)
        # ROT13 and URL decoding always produce output, but no flags in them
        # The important thing is no exception is raised
        assert isinstance(candidates, list)

    def test_empty_content_decode_and_scan(self, engine: FlagEngine):
        """Empty content should return empty list without errors."""
        candidates = engine.decode_and_scan("")
        assert isinstance(candidates, list)

    def test_results_sorted_by_confidence(self, engine: FlagEngine):
        """Results from decode_and_scan should be sorted by confidence descending."""
        flag = "flag{sorted_test}"
        encoded = base64.b64encode(flag.encode()).decode()
        candidates = engine.decode_and_scan(encoded)
        for i in range(len(candidates) - 1):
            assert candidates[i].confidence >= candidates[i + 1].confidence


# ===========================================================================
# 3. scan_binary() tests
# ===========================================================================


class TestScanBinary:
    """Tests for FlagEngine.scan_binary() method."""

    def test_binary_data_with_embedded_flag(self, engine: FlagEngine):
        """Detect flag string embedded in binary data."""
        flag = b"flag{binary_embedded}"
        data = b"\x00\x01\x02" + flag + b"\x00\xff\xfe"
        candidates = engine.scan_binary(data)
        values = [c.value for c in candidates]
        assert "flag{binary_embedded}" in values

    def test_binary_data_with_no_flags(self, engine: FlagEngine):
        """Binary data with no printable flag strings returns empty."""
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        candidates = engine.scan_binary(data)
        assert candidates == []

    def test_source_set_to_binary_scan(self, engine: FlagEngine):
        """Source field should be 'binary_scan' for binary scan results."""
        flag = b"flag{binary_source}"
        data = b"\x00" * 10 + flag + b"\x00" * 10
        candidates = engine.scan_binary(data)
        matching = [c for c in candidates if c.value == "flag{binary_source}"]
        assert len(matching) >= 1
        assert matching[0].source == "binary_scan"

    def test_binary_with_multiple_strings(self, engine: FlagEngine):
        """Detect flags among multiple printable strings in binary."""
        data = (
            b"\x00\x00hello world\x00\x00"
            b"flag{in_binary_data}\x00\x00"
            b"some other text\x00\x00"
        )
        candidates = engine.scan_binary(data)
        values = [c.value for c in candidates]
        assert "flag{in_binary_data}" in values


# ===========================================================================
# 4. validate() tests
# ===========================================================================


class TestValidate:
    """Tests for FlagEngine.validate() method."""

    def test_valid_flag_matches_format(self, engine: FlagEngine):
        """Valid flag should match the expected format."""
        assert engine.validate("flag{valid_flag}", r"flag\{[^}]+\}") is True

    def test_invalid_flag_does_not_match(self, engine: FlagEngine):
        """Invalid flag should not match the expected format."""
        assert engine.validate("not_a_flag", r"flag\{[^}]+\}") is False

    def test_invalid_regex_returns_false(self, engine: FlagEngine):
        """Invalid regex pattern should return False, not raise."""
        assert engine.validate("flag{test}", r"[invalid(") is False

    def test_empty_string_handling(self, engine: FlagEngine):
        """Empty string should not match any format."""
        assert engine.validate("", r"flag\{[^}]+\}") is False

    def test_partial_match_not_accepted(self, engine: FlagEngine):
        """Partial match should not be accepted (fullmatch required)."""
        # "flag{test} extra" should not fullmatch "flag\{[^}]+\}"
        assert engine.validate("flag{test} extra", r"flag\{[^}]+\}") is False

    def test_exact_match_accepted(self, engine: FlagEngine):
        """Exact match should be accepted."""
        assert engine.validate("CTF{exact}", r"CTF\{[^}]+\}") is True

    def test_complex_flag_format(self, engine: FlagEngine):
        """Complex flag format with special characters."""
        flag = "flag{c0mpl3x_fl@g!}"
        assert engine.validate(flag, r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?]+\}") is True


# ===========================================================================
# 5. add_format() tests
# ===========================================================================


class TestAddFormat:
    """Tests for FlagEngine.add_format() method."""

    def test_successfully_adds_new_format(self, engine: FlagEngine):
        """New format should be added to the formats list."""
        initial_count = len(engine._formats)
        engine.add_format("custom_ctf", r"MYCTF\{[^}]+\}")
        assert len(engine._formats) == initial_count + 1
        assert ("custom_ctf", r"MYCTF\{[^}]+\}") in engine._formats

    def test_new_format_used_in_subsequent_scans(self, engine: FlagEngine):
        """After adding a format, scan() should detect it."""
        engine.add_format("newformat", r"NEWF\{[^}]+\}")
        text = "The flag is NEWF{custom_registered}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "NEWF{custom_registered}" in values

    def test_invalid_regex_raises_value_error(self, engine: FlagEngine):
        """Invalid regex pattern should raise ValueError."""
        with pytest.raises(ValueError, match="无效的正则表达式"):
            engine.add_format("bad", r"[invalid(")

    def test_add_multiple_formats(self, engine: FlagEngine):
        """Multiple formats can be added sequentially."""
        engine.add_format("fmt1", r"FMT1\{[^}]+\}")
        engine.add_format("fmt2", r"FMT2\{[^}]+\}")
        text = "FMT1{first} and FMT2{second}"
        candidates = engine.scan(text)
        values = [c.value for c in candidates]
        assert "FMT1{first}" in values
        assert "FMT2{second}" in values


# ===========================================================================
# 6. _decode() tests
# ===========================================================================


class TestDecode:
    """Tests for FlagEngine._decode() internal method."""

    def test_decode_base64(self, engine: FlagEngine):
        """Base64 decoding should work for valid content."""
        original = "flag{base64_internal_test}"
        encoded = base64.b64encode(original.encode()).decode()
        result = engine._decode(encoded, "base64")
        assert result is not None
        assert "flag{base64_internal_test}" in result

    def test_decode_base32(self, engine: FlagEngine):
        """Base32 decoding should work for valid content."""
        original = "flag{base32_test_value}"
        encoded = base64.b32encode(original.encode()).decode()
        result = engine._decode(encoded, "base32")
        assert result is not None
        assert "flag{base32_test_value}" in result

    def test_decode_hex(self, engine: FlagEngine):
        """Hex decoding should work for valid content."""
        original = "flag{hex_internal}"
        encoded = original.encode().hex()
        result = engine._decode(encoded, "hex")
        assert result is not None
        assert "flag{hex_internal}" in result

    def test_decode_url(self, engine: FlagEngine):
        """URL decoding should work for percent-encoded content."""
        original = "flag{url_test}"
        encoded = urllib.parse.quote(original)
        result = engine._decode(encoded, "url")
        assert result is not None
        assert "flag{url_test}" in result

    def test_decode_rot13(self, engine: FlagEngine):
        """ROT13 decoding should work."""
        original = "flag{rot13_internal}"
        encoded = codecs.encode(original, "rot_13")
        result = engine._decode(encoded, "rot13")
        assert result is not None
        assert "flag{rot13_internal}" in result

    def test_invalid_base64_returns_none(self, engine: FlagEngine):
        """Invalid base64 content should return None."""
        result = engine._decode("!!!short!!!", "base64")
        assert result is None

    def test_invalid_hex_returns_none(self, engine: FlagEngine):
        """Invalid hex content (too short or non-hex chars) should return None."""
        result = engine._decode("xyz", "hex")
        assert result is None

    def test_unknown_encoding_returns_none(self, engine: FlagEngine):
        """Unknown encoding type should return None."""
        result = engine._decode("some content", "unknown_encoding")
        assert result is None

    def test_invalid_base32_returns_none(self, engine: FlagEngine):
        """Invalid base32 content should return None."""
        result = engine._decode("not valid base32!!!", "base32")
        assert result is None
