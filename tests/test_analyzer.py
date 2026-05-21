"""Unit tests for ChallengeAnalyzer with mocked LLM responses.

Tests cover:
- File type heuristic classification (detect_from_file)
- URL heuristic classification (_classify_from_url)
- LLM semantic classification (classify_type)
- Hint extraction (extract_hints)
- Comprehensive voting algorithm (analyze)
- Prompt template parsing
"""
from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from autopnex.ctf.analyzer import ChallengeAnalyzer
from autopnex.ctf.models import ChallengeInput, ChallengeProfile, ChallengeType


# ---------------------------------------------------------------------------
# Mock LLM Client
# ---------------------------------------------------------------------------


class MockLLMClient:
    """Mock LLM client that returns predefined responses."""

    def __init__(self, response_content: str = ""):
        self.response_content = response_content
        self.call_history: List[Dict[str, Any]] = []

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        *,
        tool_choice: str = "auto",
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> Dict[str, Any]:
        self.call_history.append({
            "messages": messages,
            "temperature": temperature,
        })
        return {
            "role": "assistant",
            "content": self.response_content,
            "tool_calls": [],
        }


class ErrorLLMClient:
    """Mock LLM client that raises exceptions."""

    def chat(self, *args, **kwargs) -> Dict[str, Any]:
        raise RuntimeError("LLM service unavailable")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_llm() -> MockLLMClient:
    """Return a mock LLM client with empty response."""
    return MockLLMClient("")


@pytest.fixture
def analyzer(mock_llm: MockLLMClient) -> ChallengeAnalyzer:
    """Return a ChallengeAnalyzer with mock LLM."""
    return ChallengeAnalyzer(llm_client=mock_llm, knowledge_base=None)


# ---------------------------------------------------------------------------
# Helper: create temp files
# ---------------------------------------------------------------------------


def create_temp_elf(with_debug: bool = False) -> Path:
    """Create a temporary file with ELF magic bytes."""
    tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    # ELF magic: 0x7f E L F
    content = b"\x7fELF" + b"\x00" * 100
    if with_debug:
        content += b".debug_info" + b"\x00" * 50
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


def create_temp_pe() -> Path:
    """Create a temporary file with PE (MZ) magic bytes."""
    tmp = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
    tmp.write(b"MZ" + b"\x00" * 200)
    tmp.close()
    return Path(tmp.name)


def create_temp_python_crypto() -> Path:
    """Create a temporary Python file with crypto keywords."""
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
    tmp.write("""
from Crypto.PublicKey import RSA
import gmpy2

n = 123456789
e = 65537
p = getPrime(512)
q = getPrime(512)
phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
""")
    tmp.close()
    return Path(tmp.name)


def create_temp_python_no_crypto() -> Path:
    """Create a temporary Python file without crypto keywords."""
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
    tmp.write("""
import os
import sys

def main():
    print("Hello, world!")

if __name__ == "__main__":
    main()
""")
    tmp.close()
    return Path(tmp.name)


def create_temp_file(suffix: str, content: str = "test") -> Path:
    """Create a temporary file with given suffix."""
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w")
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


# ===========================================================================
# Tests: detect_from_file (Task 3.3)
# ===========================================================================


class TestDetectFromFile:
    """Tests for file type heuristic classification."""

    def test_elf_binary_without_debug(self, analyzer: ChallengeAnalyzer):
        """ELF binary without debug symbols → PWN."""
        path = create_temp_elf(with_debug=False)
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.PWN
        finally:
            path.unlink(missing_ok=True)

    def test_elf_binary_with_debug(self, analyzer: ChallengeAnalyzer):
        """ELF binary with debug symbols → REVERSE."""
        path = create_temp_elf(with_debug=True)
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.REVERSE
        finally:
            path.unlink(missing_ok=True)

    def test_pe_binary(self, analyzer: ChallengeAnalyzer):
        """PE (MZ) binary → PWN."""
        path = create_temp_pe()
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.PWN
        finally:
            path.unlink(missing_ok=True)

    def test_python_with_crypto_keywords(self, analyzer: ChallengeAnalyzer):
        """Python file with crypto keywords → CRYPTO."""
        path = create_temp_python_crypto()
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.CRYPTO
        finally:
            path.unlink(missing_ok=True)

    def test_python_without_crypto_keywords(self, analyzer: ChallengeAnalyzer):
        """Python file without crypto keywords → UNKNOWN."""
        path = create_temp_python_no_crypto()
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.UNKNOWN
        finally:
            path.unlink(missing_ok=True)

    def test_sage_with_crypto(self, analyzer: ChallengeAnalyzer):
        """Sage file with crypto keywords → CRYPTO."""
        tmp = tempfile.NamedTemporaryFile(suffix=".sage", delete=False, mode="w")
        tmp.write("n = 12345\ne = 65537\nfrom sage.all import *\nmod = n\nprime = True\n")
        tmp.close()
        path = Path(tmp.name)
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.CRYPTO
        finally:
            path.unlink(missing_ok=True)

    @pytest.mark.parametrize("suffix", [".pcap", ".pcapng", ".png", ".jpg", ".pdf", ".zip"])
    def test_misc_file_types(self, analyzer: ChallengeAnalyzer, suffix: str):
        """Misc file types → MISC."""
        path = create_temp_file(suffix)
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.MISC
        finally:
            path.unlink(missing_ok=True)

    @pytest.mark.parametrize("suffix", [".php", ".html", ".js", ".jsp"])
    def test_web_file_types(self, analyzer: ChallengeAnalyzer, suffix: str):
        """Web file types → WEB."""
        path = create_temp_file(suffix)
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.WEB
        finally:
            path.unlink(missing_ok=True)

    def test_unknown_file_type(self, analyzer: ChallengeAnalyzer):
        """Unknown file type → UNKNOWN."""
        path = create_temp_file(".xyz")
        try:
            result = analyzer.detect_from_file(path)
            assert result == ChallengeType.UNKNOWN
        finally:
            path.unlink(missing_ok=True)


# ===========================================================================
# Tests: URL heuristic classification (Task 3.4)
# ===========================================================================


class TestURLClassification:
    """Tests for URL heuristic classification."""

    def test_http_url(self, analyzer: ChallengeAnalyzer):
        """http:// URL → WEB."""
        result = analyzer._classify_from_url("http://challenge.ctf.com:8080")
        assert result == ChallengeType.WEB

    def test_https_url(self, analyzer: ChallengeAnalyzer):
        """https:// URL → WEB."""
        result = analyzer._classify_from_url("https://web.ctf.com/login")
        assert result == ChallengeType.WEB

    def test_high_port_nc(self, analyzer: ChallengeAnalyzer):
        """nc with high port → PWN."""
        result = analyzer._classify_from_url("nc challenge.ctf.com 9999")
        assert result == ChallengeType.PWN

    def test_high_port_colon(self, analyzer: ChallengeAnalyzer):
        """host:high_port → PWN."""
        result = analyzer._classify_from_url("challenge.ctf.com:31337")
        assert result == ChallengeType.PWN

    def test_low_port(self, analyzer: ChallengeAnalyzer):
        """Low port (< 1024) → UNKNOWN."""
        result = analyzer._classify_from_url("challenge.ctf.com:80")
        assert result == ChallengeType.UNKNOWN

    def test_empty_url(self, analyzer: ChallengeAnalyzer):
        """Empty URL → UNKNOWN."""
        result = analyzer._classify_from_url("")
        assert result == ChallengeType.UNKNOWN

    def test_plain_hostname(self, analyzer: ChallengeAnalyzer):
        """Plain hostname without port → UNKNOWN."""
        result = analyzer._classify_from_url("challenge.ctf.com")
        assert result == ChallengeType.UNKNOWN

    def test_host_space_port(self, analyzer: ChallengeAnalyzer):
        """host port (space separated) → PWN."""
        result = analyzer._classify_from_url("challenge.ctf.com 4444")
        assert result == ChallengeType.PWN


# ===========================================================================
# Tests: classify_type (LLM classification) (Task 3.5)
# ===========================================================================


class TestClassifyType:
    """Tests for LLM semantic classification."""

    @pytest.mark.asyncio
    async def test_classify_web(self):
        """LLM returns web classification."""
        llm = MockLLMClient(json.dumps({
            "type": "web",
            "confidence": 0.9,
            "tech_stack": ["PHP", "MySQL"],
            "potential_vulns": ["SQL Injection"],
            "reasoning": "Web application with login form"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        result = await analyzer.classify_type("A web challenge with login page")
        assert result == ChallengeType.WEB

    @pytest.mark.asyncio
    async def test_classify_pwn(self):
        """LLM returns pwn classification."""
        llm = MockLLMClient(json.dumps({
            "type": "pwn",
            "confidence": 0.85,
            "tech_stack": ["C", "x86_64"],
            "potential_vulns": ["Buffer Overflow"],
            "reasoning": "Binary exploitation challenge"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        result = await analyzer.classify_type("Stack overflow in binary")
        assert result == ChallengeType.PWN

    @pytest.mark.asyncio
    async def test_classify_crypto(self):
        """LLM returns crypto classification."""
        llm = MockLLMClient(json.dumps({
            "type": "crypto",
            "confidence": 0.95,
            "tech_stack": ["RSA", "Python"],
            "potential_vulns": ["Small exponent"],
            "reasoning": "RSA with small e"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        result = await analyzer.classify_type("RSA challenge with e=3")
        assert result == ChallengeType.CRYPTO

    @pytest.mark.asyncio
    async def test_classify_with_url(self):
        """Classification includes URL context."""
        llm = MockLLMClient(json.dumps({
            "type": "web",
            "confidence": 0.8,
            "tech_stack": ["Flask"],
            "potential_vulns": ["SSTI"],
            "reasoning": "Flask web app"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        result = await analyzer.classify_type(
            "Template injection challenge",
            url="http://challenge.ctf.com:5000"
        )
        assert result == ChallengeType.WEB
        # Verify URL was included in the prompt
        assert "http://challenge.ctf.com:5000" in llm.call_history[0]["messages"][1]["content"]

    @pytest.mark.asyncio
    async def test_classify_llm_error(self):
        """LLM error returns UNKNOWN."""
        analyzer = ChallengeAnalyzer(llm_client=ErrorLLMClient())
        result = await analyzer.classify_type("Some challenge")
        assert result == ChallengeType.UNKNOWN

    @pytest.mark.asyncio
    async def test_classify_invalid_json(self):
        """Invalid JSON response returns UNKNOWN."""
        llm = MockLLMClient("This is not JSON at all")
        analyzer = ChallengeAnalyzer(llm_client=llm)
        result = await analyzer.classify_type("Some challenge")
        assert result == ChallengeType.UNKNOWN

    @pytest.mark.asyncio
    async def test_classify_json_in_markdown(self):
        """JSON wrapped in markdown code block is parsed correctly."""
        llm = MockLLMClient('```json\n{"type": "misc", "confidence": 0.7, "tech_stack": [], "potential_vulns": [], "reasoning": "steganography"}\n```')
        analyzer = ChallengeAnalyzer(llm_client=llm)
        result = await analyzer.classify_type("Hidden message in image")
        assert result == ChallengeType.MISC


# ===========================================================================
# Tests: extract_hints (Task 3.6)
# ===========================================================================


class TestExtractHints:
    """Tests for hint extraction from descriptions."""

    @pytest.mark.asyncio
    async def test_extract_hints_success(self):
        """Successfully extract hints from description."""
        llm = MockLLMClient(json.dumps([
            "PHP 7.4",
            "SQL injection in login form",
            "MySQL database",
        ]))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        hints = await analyzer.extract_hints("A PHP web app with login")
        assert len(hints) == 3
        assert "PHP 7.4" in hints
        assert "MySQL database" in hints

    @pytest.mark.asyncio
    async def test_extract_hints_empty_description(self):
        """Empty description returns empty list."""
        llm = MockLLMClient("[]")
        analyzer = ChallengeAnalyzer(llm_client=llm)
        hints = await analyzer.extract_hints("")
        assert hints == []

    @pytest.mark.asyncio
    async def test_extract_hints_llm_error(self):
        """LLM error returns empty list."""
        analyzer = ChallengeAnalyzer(llm_client=ErrorLLMClient())
        hints = await analyzer.extract_hints("Some description")
        assert hints == []

    @pytest.mark.asyncio
    async def test_extract_hints_invalid_response(self):
        """Invalid response returns empty list."""
        llm = MockLLMClient("not a json array")
        analyzer = ChallengeAnalyzer(llm_client=llm)
        hints = await analyzer.extract_hints("Some description")
        assert hints == []

    @pytest.mark.asyncio
    async def test_extract_hints_markdown_wrapped(self):
        """Hints in markdown code block are parsed."""
        llm = MockLLMClient('```json\n["RSA", "small e", "n is factorable"]\n```')
        analyzer = ChallengeAnalyzer(llm_client=llm)
        hints = await analyzer.extract_hints("RSA challenge")
        assert len(hints) == 3
        assert "RSA" in hints


# ===========================================================================
# Tests: analyze (comprehensive voting) (Task 3.7)
# ===========================================================================


class TestAnalyze:
    """Tests for the comprehensive voting algorithm."""

    @pytest.mark.asyncio
    async def test_analyze_web_from_url(self):
        """URL heuristic contributes to WEB classification."""
        llm = MockLLMClient(json.dumps({
            "type": "web",
            "confidence": 0.8,
            "tech_stack": ["PHP"],
            "potential_vulns": ["SQLi"],
            "reasoning": "Web app"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        challenge = ChallengeInput(
            target="http://challenge.ctf.com:8080",
            description="A web challenge",
        )
        profile = await analyzer.analyze(challenge)
        assert profile.challenge_type == ChallengeType.WEB
        assert 0.0 <= profile.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_pwn_from_file(self):
        """File heuristic contributes to PWN classification."""
        llm = MockLLMClient(json.dumps({
            "type": "pwn",
            "confidence": 0.7,
            "tech_stack": ["C"],
            "potential_vulns": ["Buffer Overflow"],
            "reasoning": "Binary"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        elf_path = create_temp_elf(with_debug=False)
        try:
            challenge = ChallengeInput(
                target="nc challenge.ctf.com 9999",
                description="Exploit the binary",
                attachments=[elf_path],
            )
            profile = await analyzer.analyze(challenge)
            assert profile.challenge_type == ChallengeType.PWN
            assert profile.confidence > 0.0
        finally:
            elf_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_analyze_user_specified_type(self):
        """User-specified type gets highest priority."""
        llm = MockLLMClient(json.dumps({
            "type": "web",
            "confidence": 0.9,
            "tech_stack": [],
            "potential_vulns": [],
            "reasoning": "Looks like web"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        challenge = ChallengeInput(
            target="http://challenge.ctf.com",
            description="A challenge",
            challenge_type="crypto",
        )
        profile = await analyzer.analyze(challenge)
        # User specified crypto should win over LLM's web
        assert profile.challenge_type == ChallengeType.CRYPTO

    @pytest.mark.asyncio
    async def test_analyze_no_description(self):
        """Analysis works with no description (URL heuristic only)."""
        llm = MockLLMClient("")
        analyzer = ChallengeAnalyzer(llm_client=llm)
        challenge = ChallengeInput(
            target="http://web.ctf.com:5000",
            description="",
        )
        profile = await analyzer.analyze(challenge)
        assert profile.challenge_type == ChallengeType.WEB

    @pytest.mark.asyncio
    async def test_analyze_confidence_range(self):
        """Confidence is always in [0.0, 1.0]."""
        llm = MockLLMClient(json.dumps({
            "type": "misc",
            "confidence": 0.6,
            "tech_stack": ["binwalk"],
            "potential_vulns": [],
            "reasoning": "Steganography"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        challenge = ChallengeInput(
            target="http://misc.ctf.com/download",
            description="Find the hidden message",
        )
        profile = await analyzer.analyze(challenge)
        assert 0.0 <= profile.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_tech_stack_populated(self):
        """Tech stack from LLM is included in profile."""
        llm = MockLLMClient(json.dumps({
            "type": "web",
            "confidence": 0.85,
            "tech_stack": ["Flask", "Jinja2", "Python"],
            "potential_vulns": ["SSTI"],
            "reasoning": "Flask SSTI"
        }))
        analyzer = ChallengeAnalyzer(llm_client=llm)
        challenge = ChallengeInput(
            target="http://challenge.ctf.com:5000",
            description="Flask template injection",
        )
        profile = await analyzer.analyze(challenge)
        assert "Flask" in profile.tech_stack
        assert "SSTI" in profile.potential_vulns

    @pytest.mark.asyncio
    async def test_analyze_hints_included(self):
        """User hints are included in profile key_hints."""
        # LLM returns hints extraction
        responses = [
            json.dumps({
                "type": "web",
                "confidence": 0.8,
                "tech_stack": [],
                "potential_vulns": [],
                "reasoning": "web"
            }),
            json.dumps(["hint from LLM"]),
        ]

        class MultiResponseLLM:
            def __init__(self):
                self.call_count = 0

            def chat(self, messages, *args, **kwargs):
                idx = min(self.call_count, len(responses) - 1)
                self.call_count += 1
                return {"role": "assistant", "content": responses[idx], "tool_calls": []}

        analyzer = ChallengeAnalyzer(llm_client=MultiResponseLLM())
        challenge = ChallengeInput(
            target="http://challenge.ctf.com",
            description="A web challenge",
            hints=["user provided hint"],
        )
        profile = await analyzer.analyze(challenge)
        assert "user provided hint" in profile.key_hints

    @pytest.mark.asyncio
    async def test_analyze_llm_failure_graceful(self):
        """Analysis degrades gracefully when LLM fails."""
        analyzer = ChallengeAnalyzer(llm_client=ErrorLLMClient())
        challenge = ChallengeInput(
            target="http://web.ctf.com:8080",
            description="A web challenge",
        )
        profile = await analyzer.analyze(challenge)
        # Should still classify from URL heuristic
        assert profile.challenge_type == ChallengeType.WEB

    @pytest.mark.asyncio
    async def test_analyze_unknown_when_no_signals(self):
        """Returns UNKNOWN when no classification signals available."""
        llm = MockLLMClient("")
        analyzer = ChallengeAnalyzer(llm_client=llm)
        challenge = ChallengeInput(
            target="some-target",
            description="",
        )
        profile = await analyzer.analyze(challenge)
        assert profile.challenge_type == ChallengeType.UNKNOWN
        assert profile.confidence == 0.0


# ===========================================================================
# Tests: Prompt templates (Task 3.8)
# ===========================================================================


class TestPromptTemplates:
    """Tests for CTF analysis prompt templates."""

    def test_classification_prompt_exists(self):
        """Classification prompt template is defined."""
        from autopnex.ctf.analyzer import CTF_CLASSIFICATION_PROMPT
        assert "web" in CTF_CLASSIFICATION_PROMPT
        assert "pwn" in CTF_CLASSIFICATION_PROMPT
        assert "crypto" in CTF_CLASSIFICATION_PROMPT
        assert "misc" in CTF_CLASSIFICATION_PROMPT
        assert "reverse" in CTF_CLASSIFICATION_PROMPT

    def test_hints_prompt_exists(self):
        """Hints extraction prompt template is defined."""
        from autopnex.ctf.analyzer import CTF_HINTS_EXTRACTION_PROMPT
        assert "线索" in CTF_HINTS_EXTRACTION_PROMPT or "hint" in CTF_HINTS_EXTRACTION_PROMPT.lower()

    def test_classification_prompt_json_format(self):
        """Classification prompt requests JSON format."""
        from autopnex.ctf.analyzer import CTF_CLASSIFICATION_PROMPT
        assert "JSON" in CTF_CLASSIFICATION_PROMPT or "json" in CTF_CLASSIFICATION_PROMPT


# ===========================================================================
# Tests: Internal helpers
# ===========================================================================


class TestInternalHelpers:
    """Tests for internal helper methods."""

    def test_extract_port_nc_format(self, analyzer: ChallengeAnalyzer):
        """Extract port from 'nc host port' format."""
        assert analyzer._extract_port("nc challenge.ctf.com 9999") == 9999

    def test_extract_port_colon_format(self, analyzer: ChallengeAnalyzer):
        """Extract port from 'host:port' format."""
        assert analyzer._extract_port("challenge.ctf.com:31337") == 31337

    def test_extract_port_space_format(self, analyzer: ChallengeAnalyzer):
        """Extract port from 'host port' format."""
        assert analyzer._extract_port("challenge.ctf.com 4444") == 4444

    def test_extract_port_no_port(self, analyzer: ChallengeAnalyzer):
        """No port returns None."""
        assert analyzer._extract_port("challenge.ctf.com") is None

    def test_parse_classification_valid_json(self, analyzer: ChallengeAnalyzer):
        """Parse valid JSON classification response."""
        content = json.dumps({
            "type": "web",
            "confidence": 0.9,
            "tech_stack": ["PHP"],
            "potential_vulns": ["SQLi"],
            "reasoning": "Web app"
        })
        result = analyzer._parse_classification_response(content)
        assert result == ChallengeType.WEB

    def test_parse_classification_invalid_type(self, analyzer: ChallengeAnalyzer):
        """Invalid type string returns UNKNOWN."""
        content = json.dumps({
            "type": "invalid_type",
            "confidence": 0.5,
        })
        result = analyzer._parse_classification_response(content)
        assert result == ChallengeType.UNKNOWN

    def test_parse_hints_valid_array(self, analyzer: ChallengeAnalyzer):
        """Parse valid JSON array of hints."""
        content = json.dumps(["hint1", "hint2", "hint3"])
        result = analyzer._parse_hints_response(content)
        assert result == ["hint1", "hint2", "hint3"]

    def test_parse_hints_empty_array(self, analyzer: ChallengeAnalyzer):
        """Parse empty JSON array."""
        result = analyzer._parse_hints_response("[]")
        assert result == []

    def test_parse_hints_not_array(self, analyzer: ChallengeAnalyzer):
        """Non-array JSON returns empty list."""
        result = analyzer._parse_hints_response('{"key": "value"}')
        assert result == []
