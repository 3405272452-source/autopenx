"""Unit tests for AIGradingCache.

Tests cover:
- put/get round-trip (cache hit within TTL)
- get returns None for expired entries (TTL > 7 days)
- get returns None for non-existent fingerprints
- invalidate removes entries
- invalidate returns False for non-existent entries
- compute_fingerprint is a pure function (same inputs → same output)
- put with same fingerprint replaces existing entry (upsert)

Requirements: 15.7
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest

from cet4_app.domain.models.ai_grading import (
    AIGradingResult,
    AIIssue,
    DimensionScores,
)
from cet4_app.domain.enums import IssueCategory
from cet4_app.infrastructure.deepseek.cache import (
    AIGradingCache,
    compute_fingerprint,
)
from cet4_app.infrastructure.persistence.db import create_engine, init_schema


@pytest.fixture
def cache(tmp_path: Path) -> AIGradingCache:
    """Create a fresh SQLite-backed cache for each test."""
    db_path = tmp_path / "test_cache.db"
    engine = create_engine(db_path)
    init_schema(engine)
    return AIGradingCache(engine)


def _make_fingerprint(
    user_answer: str = "My essay text",
    model: str = "deepseek-v4-flash",
    reference_answer: str = "Reference essay",
) -> str:
    """Compute a fingerprint for test data."""
    return compute_fingerprint(user_answer, model, reference_answer)


def _make_result(
    fingerprint: str | None = None,
    generated_at: datetime | None = None,
) -> AIGradingResult:
    """Create a valid AIGradingResult for testing."""
    if fingerprint is None:
        fingerprint = _make_fingerprint()
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)

    return AIGradingResult(
        result_id="result-001",
        question_id="2024-12-set1-writing-writing-01",
        sheet_id="sheet-001",
        model="deepseek-v4-flash",
        dimension_scores=DimensionScores(
            content=4, structure=3, language=4, word_count=5
        ),
        overall_score=Decimal("80.00"),
        comments={
            "content": "内容丰富，论点明确，论据充分，逻辑清晰，表达流畅。",
            "structure": "结构合理，段落分明，过渡自然，首尾呼应，层次清晰。",
            "language": "语言准确，用词恰当，句式多样，语法正确，表达地道。",
            "word_count": "字数达标，篇幅适中，内容充实，详略得当，重点突出。",
        },
        highlights=["Good use of transitional phrases"],
        issues=[
            AIIssue(
                span="This is a example",
                category=IssueCategory.grammar,
                suggestion="Should be 'an example' instead of 'a example'.",
            )
        ],
        revised_version=" ".join(["word"] * 150),
        context_truncated=False,
        from_cache=False,
        generated_at=generated_at,
        input_fingerprint=fingerprint,
    )


class TestComputeFingerprint:
    """Tests for the compute_fingerprint pure function."""

    def test_returns_64_char_hex(self):
        fp = compute_fingerprint("answer", "model", "ref")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        """Same inputs always produce the same fingerprint."""
        fp1 = compute_fingerprint("hello", "deepseek-v4-flash", "world")
        fp2 = compute_fingerprint("hello", "deepseek-v4-flash", "world")
        assert fp1 == fp2

    def test_different_inputs_different_fingerprints(self):
        fp1 = compute_fingerprint("answer1", "model", "ref")
        fp2 = compute_fingerprint("answer2", "model", "ref")
        assert fp1 != fp2

    def test_matches_sha256_of_pipe_separated(self):
        """Fingerprint equals sha256 of 'user_answer|model|reference_answer'."""
        user = "my answer"
        model = "deepseek-v4-flash"
        ref = "reference"
        expected = hashlib.sha256(f"{user}|{model}|{ref}".encode("utf-8")).hexdigest()
        assert compute_fingerprint(user, model, ref) == expected

    def test_empty_strings(self):
        """Works with empty reference_answer."""
        fp = compute_fingerprint("answer", "model", "")
        assert len(fp) == 64

    def test_unicode_content(self):
        """Handles Chinese/Unicode content correctly."""
        fp = compute_fingerprint("这是我的作文", "deepseek-v4-flash", "参考范文")
        assert len(fp) == 64


class TestCacheGet:
    """Tests for AIGradingCache.get()."""

    def test_get_nonexistent_returns_none(self, cache: AIGradingCache):
        result = cache.get("a" * 64)
        assert result is None

    def test_get_after_put_returns_result(self, cache: AIGradingCache):
        fp = _make_fingerprint()
        original = _make_result(fingerprint=fp)
        cache.put(fp, original)

        cached = cache.get(fp)
        assert cached is not None
        assert cached.result_id == "result-001"
        assert cached.question_id == "2024-12-set1-writing-writing-01"
        assert cached.model == "deepseek-v4-flash"
        assert cached.from_cache is True
        assert cached.input_fingerprint == fp

    def test_get_expired_returns_none(self, cache: AIGradingCache):
        """Entries older than 7 days are treated as expired."""
        fp = _make_fingerprint()
        # Create a result generated 8 days ago
        old_time = datetime.now(timezone.utc) - timedelta(days=8)
        old_result = _make_result(fingerprint=fp, generated_at=old_time)
        cache.put(fp, old_result)

        # Should return None because it's expired
        cached = cache.get(fp)
        assert cached is None

    def test_get_within_ttl_returns_result(self, cache: AIGradingCache):
        """Entries within 7 days are valid."""
        fp = _make_fingerprint()
        # Created 6 days ago — still valid
        recent_time = datetime.now(timezone.utc) - timedelta(days=6)
        result = _make_result(fingerprint=fp, generated_at=recent_time)
        cache.put(fp, result)

        cached = cache.get(fp)
        assert cached is not None
        assert cached.from_cache is True

    def test_get_preserves_dimension_scores(self, cache: AIGradingCache):
        fp = _make_fingerprint()
        original = _make_result(fingerprint=fp)
        cache.put(fp, original)

        cached = cache.get(fp)
        assert cached is not None
        assert cached.dimension_scores.content == 4
        assert cached.dimension_scores.structure == 3
        assert cached.dimension_scores.language == 4
        assert cached.dimension_scores.word_count == 5

    def test_get_preserves_comments(self, cache: AIGradingCache):
        fp = _make_fingerprint()
        original = _make_result(fingerprint=fp)
        cache.put(fp, original)

        cached = cache.get(fp)
        assert cached is not None
        assert set(cached.comments.keys()) == {"content", "structure", "language", "word_count"}

    def test_get_preserves_issues(self, cache: AIGradingCache):
        fp = _make_fingerprint()
        original = _make_result(fingerprint=fp)
        cache.put(fp, original)

        cached = cache.get(fp)
        assert cached is not None
        assert len(cached.issues) == 1
        assert cached.issues[0].category == IssueCategory.grammar
        assert cached.issues[0].span == "This is a example"


class TestCachePut:
    """Tests for AIGradingCache.put()."""

    def test_put_upsert_replaces_existing(self, cache: AIGradingCache):
        """Putting with the same fingerprint replaces the old entry."""
        fp = _make_fingerprint()
        result1 = _make_result(fingerprint=fp)
        cache.put(fp, result1)

        # Create a new result with same fingerprint but different result_id
        result2 = AIGradingResult(
            result_id="result-002",
            question_id="2024-12-set1-writing-writing-01",
            sheet_id="sheet-002",
            model="deepseek-v4-flash",
            dimension_scores=DimensionScores(
                content=5, structure=5, language=5, word_count=5
            ),
            overall_score=Decimal("95.00"),
            comments={
                "content": "内容丰富，论点明确，论据充分，逻辑清晰，表达流畅。",
                "structure": "结构合理，段落分明，过渡自然，首尾呼应，层次清晰。",
                "language": "语言准确，用词恰当，句式多样，语法正确，表达地道。",
                "word_count": "字数达标，篇幅适中，内容充实，详略得当，重点突出。",
            },
            highlights=[],
            issues=[],
            revised_version=" ".join(["word"] * 150),
            context_truncated=False,
            from_cache=False,
            generated_at=datetime.now(timezone.utc),
            input_fingerprint=fp,
        )
        cache.put(fp, result2)

        cached = cache.get(fp)
        assert cached is not None
        assert cached.result_id == "result-002"
        assert cached.overall_score == Decimal("95.00")


class TestCacheInvalidate:
    """Tests for AIGradingCache.invalidate()."""

    def test_invalidate_existing_returns_true(self, cache: AIGradingCache):
        fp = _make_fingerprint()
        cache.put(fp, _make_result(fingerprint=fp))

        assert cache.invalidate(fp) is True

    def test_invalidate_removes_entry(self, cache: AIGradingCache):
        fp = _make_fingerprint()
        cache.put(fp, _make_result(fingerprint=fp))
        cache.invalidate(fp)

        assert cache.get(fp) is None

    def test_invalidate_nonexistent_returns_false(self, cache: AIGradingCache):
        assert cache.invalidate("b" * 64) is False
