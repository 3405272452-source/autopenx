"""CTF 知识库单元测试 — CTFKnowledgeBase 和 CTFKnowledgeRetriever。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from autopnex.ctf.knowledge_base import CTFKnowledgeBase, CTFKnowledgeRetriever
from autopnex.ctf.models import ChallengeProfile, ChallengeType


# ══════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def kb() -> CTFKnowledgeBase:
    """Create an in-memory knowledge base (no persistence)."""
    return CTFKnowledgeBase(storage_path=None)


@pytest.fixture()
def kb_with_storage(tmp_path) -> CTFKnowledgeBase:
    """Create a knowledge base with file persistence."""
    storage = tmp_path / "kb_data.json"
    return CTFKnowledgeBase(storage_path=storage)


@pytest.fixture()
def web_profile() -> ChallengeProfile:
    """Create a sample Web challenge profile."""
    return ChallengeProfile(
        challenge_type=ChallengeType.WEB,
        sub_type="sqli",
        tech_stack=["php", "mysql"],
        potential_vulns=["sqli", "lfi"],
        key_hints=["login form", "error messages"],
        confidence=0.85,
    )


@pytest.fixture()
def crypto_profile() -> ChallengeProfile:
    """Create a sample Crypto challenge profile."""
    return ChallengeProfile(
        challenge_type=ChallengeType.CRYPTO,
        sub_type="rsa",
        tech_stack=["python", "pycryptodome"],
        potential_vulns=[],
        key_hints=["small e", "n is factorable"],
        confidence=0.9,
    )


@pytest.fixture()
def misc_profile() -> ChallengeProfile:
    """Create a sample Misc challenge profile."""
    return ChallengeProfile(
        challenge_type=ChallengeType.MISC,
        sub_type="steganography",
        tech_stack=["png", "steghide"],
        potential_vulns=[],
        key_hints=["hidden data in image"],
        confidence=0.7,
    )


# ══════════════════════════════════════════════════════════════════════════
# Test __init__
# ══════════════════════════════════════════════════════════════════════════


class TestInit:
    """Test CTFKnowledgeBase initialization."""

    def test_init_without_storage_path(self, kb: CTFKnowledgeBase):
        """Init with no storage_path creates in-memory KB."""
        assert kb.storage_path is None
        assert kb.solve_records == []
        # Builtin data should be loaded
        assert isinstance(kb.payloads, dict)
        assert isinstance(kb.patterns, dict)

    def test_init_with_storage_path_nonexistent(self, tmp_path):
        """Init with non-existent storage_path creates empty KB."""
        storage = tmp_path / "nonexistent.json"
        kb = CTFKnowledgeBase(storage_path=storage)
        assert kb.storage_path == storage
        assert kb.solve_records == []

    def test_init_with_existing_storage(self, tmp_path):
        """Init with existing storage file loads data."""
        storage = tmp_path / "kb.json"
        # Pre-populate storage file
        data = {
            "solve_records": [
                {
                    "timestamp": 1700000000.0,
                    "challenge_type": "web",
                    "sub_type": "sqli",
                    "tech_stack": ["php"],
                    "potential_vulns": ["sqli"],
                    "key_hints": [],
                    "difficulty_estimate": "easy",
                    "confidence": 0.9,
                    "flag": "flag{test}",
                    "target": "http://example.com",
                    "steps_executed": 3,
                    "duration_ms": 5000,
                    "strategy_used": "union injection",
                }
            ]
        }
        storage.write_text(json.dumps(data), encoding="utf-8")

        kb = CTFKnowledgeBase(storage_path=storage)
        assert len(kb.solve_records) == 1
        assert kb.solve_records[0]["flag"] == "flag{test}"

    def test_init_loads_builtin_payloads(self, kb: CTFKnowledgeBase):
        """Builtin payloads are loaded from data files."""
        # Should have at least sqli payloads from the builtin file
        assert "sqli" in kb.payloads
        assert len(kb.payloads["sqli"]) > 0

    def test_init_loads_builtin_patterns(self, kb: CTFKnowledgeBase):
        """Builtin patterns are loaded from data files."""
        assert "web" in kb.patterns
        assert len(kb.patterns["web"]) > 0


# ══════════════════════════════════════════════════════════════════════════
# Test record_solve
# ══════════════════════════════════════════════════════════════════════════


class TestRecordSolve:
    """Test CTFKnowledgeBase.record_solve()."""

    def test_record_solve_stores_data(self, kb: CTFKnowledgeBase, web_profile):
        """record_solve adds a record to solve_records."""
        solution = {
            "flag": "flag{sql_injection_success}",
            "target": "http://vuln.ctf.com",
            "steps_executed": 5,
            "duration_ms": 12000,
            "strategy_used": "union-based sqli",
        }
        kb.record_solve(web_profile, solution)

        assert len(kb.solve_records) == 1
        record = kb.solve_records[0]
        assert record["challenge_type"] == "web"
        assert record["sub_type"] == "sqli"
        assert record["tech_stack"] == ["php", "mysql"]
        assert record["flag"] == "flag{sql_injection_success}"
        assert record["steps_executed"] == 5
        assert "timestamp" in record

    def test_record_solve_multiple(self, kb: CTFKnowledgeBase, web_profile, crypto_profile):
        """Multiple solves accumulate in solve_records."""
        kb.record_solve(web_profile, {"flag": "flag{web1}"})
        kb.record_solve(crypto_profile, {"flag": "flag{crypto1}"})

        assert len(kb.solve_records) == 2
        assert kb.solve_records[0]["challenge_type"] == "web"
        assert kb.solve_records[1]["challenge_type"] == "crypto"

    def test_record_solve_persists_to_file(self, kb_with_storage, web_profile):
        """record_solve persists data to storage file."""
        solution = {"flag": "flag{persisted}"}
        kb_with_storage.record_solve(web_profile, solution)

        # Verify file was written
        assert kb_with_storage.storage_path.exists()
        data = json.loads(kb_with_storage.storage_path.read_text(encoding="utf-8"))
        assert len(data["solve_records"]) == 1
        assert data["solve_records"][0]["flag"] == "flag{persisted}"

    def test_record_solve_includes_timestamp(self, kb: CTFKnowledgeBase, web_profile):
        """record_solve includes a timestamp."""
        kb.record_solve(web_profile, {"flag": "flag{ts}"})
        record = kb.solve_records[0]
        assert "timestamp" in record
        assert isinstance(record["timestamp"], float)
        assert record["timestamp"] > 0


# ══════════════════════════════════════════════════════════════════════════
# Test query_similar
# ══════════════════════════════════════════════════════════════════════════


class TestQuerySimilar:
    """Test CTFKnowledgeBase.query_similar()."""

    def test_query_similar_empty_kb(self, kb: CTFKnowledgeBase):
        """query_similar returns empty list when no records exist."""
        results = kb.query_similar(ChallengeType.WEB, tech_stack=["php"])
        assert results == []

    def test_query_similar_returns_matching_type(self, kb: CTFKnowledgeBase, web_profile):
        """query_similar returns records matching challenge_type."""
        kb.record_solve(web_profile, {"flag": "flag{web}"})
        kb.record_solve(
            ChallengeProfile(challenge_type=ChallengeType.CRYPTO, confidence=0.8),
            {"flag": "flag{crypto}"},
        )

        results = kb.query_similar(ChallengeType.WEB, tech_stack=["php"])
        assert len(results) >= 1
        assert results[0]["challenge_type"] == "web"

    def test_query_similar_scores_by_tech_stack(self, kb: CTFKnowledgeBase):
        """query_similar ranks results by tech_stack overlap."""
        # Record with matching tech stack
        profile_match = ChallengeProfile(
            challenge_type=ChallengeType.WEB,
            tech_stack=["php", "mysql", "apache"],
            confidence=0.8,
        )
        kb.record_solve(profile_match, {"flag": "flag{match}"})

        # Record with different tech stack
        profile_nomatch = ChallengeProfile(
            challenge_type=ChallengeType.WEB,
            tech_stack=["java", "spring"],
            confidence=0.8,
        )
        kb.record_solve(profile_nomatch, {"flag": "flag{nomatch}"})

        results = kb.query_similar(ChallengeType.WEB, tech_stack=["php", "mysql"])
        assert len(results) == 2
        # The one with more tech_stack overlap should rank first
        assert results[0]["flag"] == "flag{match}"

    def test_query_similar_respects_limit(self, kb: CTFKnowledgeBase):
        """query_similar respects the limit parameter."""
        for i in range(10):
            profile = ChallengeProfile(
                challenge_type=ChallengeType.WEB,
                tech_stack=["php"],
                confidence=0.8,
            )
            kb.record_solve(profile, {"flag": f"flag{{web_{i}}}"})

        results = kb.query_similar(ChallengeType.WEB, tech_stack=["php"], limit=3)
        assert len(results) == 3

    def test_query_similar_with_profile_object(self, kb: CTFKnowledgeBase, web_profile):
        """query_similar works with ChallengeProfile as first argument."""
        kb.record_solve(web_profile, {"flag": "flag{compat}"})

        # Use profile object directly (backward compatibility)
        results = kb.query_similar(web_profile)
        assert len(results) >= 1

    def test_query_similar_no_match_returns_empty(self, kb: CTFKnowledgeBase):
        """query_similar returns empty when no type matches."""
        profile = ChallengeProfile(
            challenge_type=ChallengeType.WEB,
            tech_stack=["php"],
            confidence=0.8,
        )
        kb.record_solve(profile, {"flag": "flag{web}"})

        # Query for a different type with no overlap
        results = kb.query_similar(ChallengeType.REVERSE, tech_stack=["ghidra"])
        assert results == []


# ══════════════════════════════════════════════════════════════════════════
# Test get_payloads
# ══════════════════════════════════════════════════════════════════════════


class TestGetPayloads:
    """Test CTFKnowledgeBase.get_payloads()."""

    def test_get_payloads_by_vuln_type(self, kb: CTFKnowledgeBase):
        """get_payloads returns payloads for a given vuln type string."""
        payloads = kb.get_payloads("sqli")
        assert len(payloads) > 0
        assert any("UNION" in p or "OR" in p for p in payloads)

    def test_get_payloads_by_challenge_type(self, kb: CTFKnowledgeBase):
        """get_payloads returns payloads for a ChallengeType."""
        payloads = kb.get_payloads(ChallengeType.WEB)
        assert len(payloads) > 0

    def test_get_payloads_with_sub_type_filter(self, kb: CTFKnowledgeBase):
        """get_payloads filters by sub_type."""
        payloads = kb.get_payloads("sqli", sub_type="mysql")
        assert len(payloads) > 0
        # MySQL-specific payloads should include MySQL keywords
        assert any("@@version" in p or "SLEEP" in p or "information_schema" in p for p in payloads)

    def test_get_payloads_unknown_type_returns_empty(self, kb: CTFKnowledgeBase):
        """get_payloads returns empty list for unknown type."""
        payloads = kb.get_payloads("nonexistent_vuln_type")
        assert payloads == []

    def test_get_payloads_crypto_type(self, kb: CTFKnowledgeBase):
        """get_payloads returns crypto payloads."""
        payloads = kb.get_payloads("crypto", sub_type="rsa")
        assert len(payloads) > 0

    def test_get_payloads_misc_type(self, kb: CTFKnowledgeBase):
        """get_payloads returns misc payloads."""
        payloads = kb.get_payloads("misc", sub_type="steganography")
        assert len(payloads) > 0

    def test_get_payloads_with_tech_stack(self, kb: CTFKnowledgeBase):
        """get_payloads filters by tech_stack."""
        payloads = kb.get_payloads("sqli", tech_stack=["mysql"])
        assert len(payloads) > 0


# ══════════════════════════════════════════════════════════════════════════
# Test get_common_patterns
# ══════════════════════════════════════════════════════════════════════════


class TestGetCommonPatterns:
    """Test CTFKnowledgeBase.get_common_patterns()."""

    def test_get_common_patterns_web(self, kb: CTFKnowledgeBase):
        """get_common_patterns returns patterns for Web type."""
        patterns = kb.get_common_patterns(ChallengeType.WEB)
        assert len(patterns) >= 3
        # Each pattern should have required fields
        for p in patterns:
            assert "name" in p
            assert "description" in p
            assert "steps" in p
            assert "success_rate" in p

    def test_get_common_patterns_crypto(self, kb: CTFKnowledgeBase):
        """get_common_patterns returns patterns for Crypto type."""
        patterns = kb.get_common_patterns(ChallengeType.CRYPTO)
        assert len(patterns) >= 3

    def test_get_common_patterns_misc(self, kb: CTFKnowledgeBase):
        """get_common_patterns returns patterns for Misc type."""
        patterns = kb.get_common_patterns(ChallengeType.MISC)
        assert len(patterns) >= 3

    def test_get_common_patterns_pwn(self, kb: CTFKnowledgeBase):
        """get_common_patterns returns patterns for Pwn type."""
        patterns = kb.get_common_patterns(ChallengeType.PWN)
        assert len(patterns) >= 3

    def test_get_common_patterns_reverse(self, kb: CTFKnowledgeBase):
        """get_common_patterns returns patterns for Reverse type."""
        patterns = kb.get_common_patterns(ChallengeType.REVERSE)
        assert len(patterns) >= 3

    def test_get_common_patterns_unknown_returns_empty(self, kb: CTFKnowledgeBase):
        """get_common_patterns returns empty for Unknown type."""
        patterns = kb.get_common_patterns(ChallengeType.UNKNOWN)
        assert patterns == []

    def test_pattern_has_success_rate(self, kb: CTFKnowledgeBase):
        """Each pattern has a numeric success_rate."""
        patterns = kb.get_common_patterns(ChallengeType.WEB)
        for p in patterns:
            assert isinstance(p["success_rate"], (int, float))
            assert 0.0 <= p["success_rate"] <= 1.0


# ══════════════════════════════════════════════════════════════════════════
# Test CTFKnowledgeRetriever
# ══════════════════════════════════════════════════════════════════════════


class TestCTFKnowledgeRetriever:
    """Test CTFKnowledgeRetriever three-stage retrieval."""

    def test_retrieve_returns_dict_with_three_keys(self, kb: CTFKnowledgeBase, web_profile):
        """retrieve returns dict with similar_solves, payloads, patterns."""
        retriever = CTFKnowledgeRetriever(kb)
        result = retriever.retrieve(web_profile)

        assert "similar_solves" in result
        assert "payloads" in result
        assert "patterns" in result

    def test_retrieve_stage1_similar_solves(self, kb: CTFKnowledgeBase, web_profile):
        """Stage 1: retrieve returns similar past solves."""
        # Add a solve record first
        kb.record_solve(web_profile, {"flag": "flag{past_solve}"})

        retriever = CTFKnowledgeRetriever(kb)
        result = retriever.retrieve(web_profile)

        assert len(result["similar_solves"]) >= 1
        assert result["similar_solves"][0]["flag"] == "flag{past_solve}"

    def test_retrieve_stage2_payloads(self, kb: CTFKnowledgeBase, web_profile):
        """Stage 2: retrieve returns relevant payloads."""
        retriever = CTFKnowledgeRetriever(kb)
        result = retriever.retrieve(web_profile)

        # Web profile with sqli potential_vulns should get sqli payloads
        assert len(result["payloads"]) > 0

    def test_retrieve_stage3_patterns(self, kb: CTFKnowledgeBase, web_profile):
        """Stage 3: retrieve returns common patterns."""
        retriever = CTFKnowledgeRetriever(kb)
        result = retriever.retrieve(web_profile)

        assert len(result["patterns"]) >= 3
        # Patterns should be for the Web type
        pattern_names = [p["name"] for p in result["patterns"]]
        assert any("SQL" in name or "XSS" in name or "LFI" in name for name in pattern_names)

    def test_retrieve_crypto_profile(self, kb: CTFKnowledgeBase, crypto_profile):
        """retrieve works for Crypto profiles."""
        retriever = CTFKnowledgeRetriever(kb)
        result = retriever.retrieve(crypto_profile)

        assert len(result["patterns"]) >= 3
        pattern_names = [p["name"] for p in result["patterns"]]
        assert any("RSA" in name or "Cipher" in name or "XOR" in name for name in pattern_names)

    def test_retrieve_misc_profile(self, kb: CTFKnowledgeBase, misc_profile):
        """retrieve works for Misc profiles."""
        retriever = CTFKnowledgeRetriever(kb)
        result = retriever.retrieve(misc_profile)

        assert len(result["patterns"]) >= 3

    def test_retrieve_empty_kb_still_returns_patterns(self, kb: CTFKnowledgeBase, web_profile):
        """retrieve returns patterns even with no solve records."""
        retriever = CTFKnowledgeRetriever(kb)
        result = retriever.retrieve(web_profile)

        # No solves recorded, but patterns and payloads should still be available
        assert result["similar_solves"] == []
        assert len(result["patterns"]) > 0
        assert len(result["payloads"]) > 0


# ══════════════════════════════════════════════════════════════════════════
# Test Persistence (write and reload)
# ══════════════════════════════════════════════════════════════════════════


class TestPersistence:
    """Test knowledge base persistence (write and reload)."""

    def test_persist_and_reload(self, tmp_path, web_profile):
        """Data persisted to file can be reloaded by a new instance."""
        storage = tmp_path / "persist_test.json"

        # Create KB and record a solve
        kb1 = CTFKnowledgeBase(storage_path=storage)
        kb1.record_solve(web_profile, {"flag": "flag{persist_test}", "steps_executed": 7})

        # Create a new KB instance from the same file
        kb2 = CTFKnowledgeBase(storage_path=storage)
        assert len(kb2.solve_records) == 1
        assert kb2.solve_records[0]["flag"] == "flag{persist_test}"
        assert kb2.solve_records[0]["steps_executed"] == 7

    def test_persist_multiple_records(self, tmp_path, web_profile, crypto_profile):
        """Multiple records are persisted and reloaded correctly."""
        storage = tmp_path / "multi_persist.json"

        kb1 = CTFKnowledgeBase(storage_path=storage)
        kb1.record_solve(web_profile, {"flag": "flag{web1}"})
        kb1.record_solve(crypto_profile, {"flag": "flag{crypto1}"})

        kb2 = CTFKnowledgeBase(storage_path=storage)
        assert len(kb2.solve_records) == 2
        types = [r["challenge_type"] for r in kb2.solve_records]
        assert "web" in types
        assert "crypto" in types

    def test_persist_creates_parent_dirs(self, tmp_path, web_profile):
        """Persistence creates parent directories if they don't exist."""
        storage = tmp_path / "nested" / "dir" / "kb.json"

        kb = CTFKnowledgeBase(storage_path=storage)
        kb.record_solve(web_profile, {"flag": "flag{nested}"})

        assert storage.exists()

    def test_no_persist_without_storage_path(self, kb: CTFKnowledgeBase, web_profile):
        """In-memory KB does not write to disk."""
        kb.record_solve(web_profile, {"flag": "flag{memory_only}"})
        # No file should be created (storage_path is None)
        assert kb.storage_path is None
        assert len(kb.solve_records) == 1

    def test_corrupt_file_handled_gracefully(self, tmp_path):
        """Corrupt storage file is handled without crashing."""
        storage = tmp_path / "corrupt.json"
        storage.write_text("not valid json {{{", encoding="utf-8")

        # Should not raise, just log a warning
        kb = CTFKnowledgeBase(storage_path=storage)
        assert kb.solve_records == []
