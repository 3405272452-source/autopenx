"""Integration tests for AI grading cache and log subsystems.

Covers:
1. Cache hit: same fingerprint within 7 days returns cached result.
2. Cache miss/expiry: entries older than 7 days return None.
3. Cache invalidation: invalidate() removes the entry.
4. Log field whitelist: ai_grading_log entries contain only allowed fields
   (no API key, no user answer text) — Req 15.11.
5. 30-day log cleanup: logs older than 30 days are removed — Req 14.5.

Requirements: 15.7, 15.11
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import text

from cet4_app.domain.enums import IssueCategory
from cet4_app.domain.models.ai_grading import (
    AIGradingResult,
    AIIssue,
    DimensionScores,
)
from cet4_app.infrastructure.deepseek.cache import AIGradingCache, compute_fingerprint
from cet4_app.infrastructure.persistence.db import create_engine, init_schema, transaction
from cet4_app.infrastructure.repositories.log_repo import LogRepo


@pytest.fixture
def engine(tmp_path: Path):
    """Create a fresh SQLite engine with full schema for each test."""
    db_path = tmp_path / "test_integration.db"
    eng = create_engine(db_path)
    init_schema(eng)
    return eng


@pytest.fixture
def cache(engine) -> AIGradingCache:
    """AIGradingCache backed by the test engine."""
    return AIGradingCache(engine)


@pytest.fixture
def log_repo(engine) -> LogRepo:
    """LogRepo backed by the test engine."""
    return LogRepo(engine)


def _make_result(
    fingerprint: str,
    generated_at: datetime | None = None,
) -> AIGradingResult:
    """Create a valid AIGradingResult for testing."""
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)

    return AIGradingResult(
        result_id="result-int-001",
        question_id="2024-12-set1-writing-writing-01",
        sheet_id="sheet-int-001",
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
        highlights=["Good transitional phrases"],
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


# ======================================================================
# 1. Cache hit: same fingerprint within 7 days returns cached result
# ======================================================================


class TestCacheHitWithin7Days:
    """Same fingerprint < 7 days returns cached result."""

    def test_immediate_cache_hit(self, cache: AIGradingCache):
        """A result stored just now is immediately retrievable."""
        fp = compute_fingerprint("my essay", "deepseek-v4-flash", "reference")
        result = _make_result(fp)
        cache.put(fp, result)

        cached = cache.get(fp)
        assert cached is not None
        assert cached.from_cache is True
        assert cached.result_id == "result-int-001"
        assert cached.input_fingerprint == fp

    def test_cache_hit_at_6_days(self, cache: AIGradingCache):
        """A result generated 6 days ago is still valid (within 7-day TTL)."""
        fp = compute_fingerprint("essay text", "deepseek-v4-flash", "ref text")
        generated = datetime.now(timezone.utc) - timedelta(days=6)
        result = _make_result(fp, generated_at=generated)
        cache.put(fp, result)

        cached = cache.get(fp)
        assert cached is not None
        assert cached.from_cache is True

    def test_cache_hit_preserves_all_fields(self, cache: AIGradingCache):
        """Cached result preserves dimension_scores, comments, issues, etc."""
        fp = compute_fingerprint("full test", "deepseek-v4-flash", "full ref")
        result = _make_result(fp)
        cache.put(fp, result)

        cached = cache.get(fp)
        assert cached is not None
        assert cached.dimension_scores.content == 4
        assert cached.dimension_scores.structure == 3
        assert cached.dimension_scores.language == 4
        assert cached.dimension_scores.word_count == 5
        assert cached.overall_score == Decimal("80.00")
        assert set(cached.comments.keys()) == {"content", "structure", "language", "word_count"}
        assert len(cached.issues) == 1
        assert cached.issues[0].category == IssueCategory.grammar


# ======================================================================
# 2. Cache miss/expiry: entries older than 7 days return None
# ======================================================================


class TestCacheExpiry:
    """Entries older than 7 days are treated as expired."""

    def test_expired_at_8_days(self, cache: AIGradingCache):
        """A result generated 8 days ago is expired and returns None."""
        fp = compute_fingerprint("old essay", "deepseek-v4-flash", "old ref")
        generated = datetime.now(timezone.utc) - timedelta(days=8)
        result = _make_result(fp, generated_at=generated)
        cache.put(fp, result)

        cached = cache.get(fp)
        assert cached is None

    def test_expired_at_exactly_7_days_plus_1_second(self, cache: AIGradingCache):
        """A result generated 7 days + 1 second ago is expired."""
        fp = compute_fingerprint("boundary essay", "deepseek-v4-flash", "boundary ref")
        generated = datetime.now(timezone.utc) - timedelta(days=7, seconds=1)
        result = _make_result(fp, generated_at=generated)
        cache.put(fp, result)

        cached = cache.get(fp)
        assert cached is None

    def test_nonexistent_fingerprint_returns_none(self, cache: AIGradingCache):
        """A fingerprint that was never stored returns None."""
        fp = "a" * 64
        cached = cache.get(fp)
        assert cached is None


# ======================================================================
# 3. Cache invalidation: invalidate() removes the entry
# ======================================================================


class TestCacheInvalidation:
    """invalidate() removes the cached entry."""

    def test_invalidate_removes_entry(self, cache: AIGradingCache):
        """After invalidation, get() returns None."""
        fp = compute_fingerprint("to invalidate", "deepseek-v4-flash", "ref")
        result = _make_result(fp)
        cache.put(fp, result)

        # Verify it exists first
        assert cache.get(fp) is not None

        # Invalidate
        removed = cache.invalidate(fp)
        assert removed is True

        # Now it's gone
        assert cache.get(fp) is None

    def test_invalidate_nonexistent_returns_false(self, cache: AIGradingCache):
        """Invalidating a non-existent entry returns False."""
        fp = "b" * 64
        removed = cache.invalidate(fp)
        assert removed is False


# ======================================================================
# 4. Log field whitelist: ai_grading_log entries contain only allowed
#    fields (no API key, no user answer text) — Req 15.11
# ======================================================================

#: The complete set of columns allowed in ai_grading_log per Req 15.11.
_ALLOWED_LOG_COLUMNS = frozenset({
    "log_id",
    "question_id",
    "model",
    "http_status",
    "duration_ms",
    "prompt_tokens",
    "completion_tokens",
    "from_cache",
    "context_truncated",
    "created_at",
})

#: Fields that MUST NOT appear in ai_grading_log (Req 15.11).
_FORBIDDEN_FIELDS = frozenset({"api_key", "user_answer"})


class TestLogFieldWhitelist:
    """ai_grading_log entries contain only allowed fields (Req 15.11)."""

    def test_grading_log_columns_match_whitelist(self, engine):
        """The ai_grading_log table has exactly the allowed columns."""
        with engine.connect() as conn:
            rows = conn.execute(text("PRAGMA table_info(ai_grading_log)")).fetchall()

        actual_columns = {row[1] for row in rows}
        assert actual_columns == _ALLOWED_LOG_COLUMNS

    def test_grading_log_does_not_contain_forbidden_fields(self, engine):
        """The ai_grading_log table does NOT have api_key or user_answer columns."""
        with engine.connect() as conn:
            rows = conn.execute(text("PRAGMA table_info(ai_grading_log)")).fetchall()

        actual_columns = {row[1] for row in rows}
        for forbidden in _FORBIDDEN_FIELDS:
            assert forbidden not in actual_columns, (
                f"Forbidden field '{forbidden}' found in ai_grading_log table"
            )

    def test_insert_grading_log_stores_only_metadata(self, log_repo: LogRepo):
        """insert_grading_log stores metadata without api_key or user_answer."""
        log_id = log_repo.insert_grading_log(
            question_id="2024-12-set1-writing-writing-01",
            model="deepseek-v4-flash",
            http_status=200,
            duration_ms=1500,
            prompt_tokens=800,
            completion_tokens=512,
            from_cache=False,
            context_truncated=True,
        )

        logs = log_repo.query_grading_logs(
            question_id="2024-12-set1-writing-writing-01"
        )
        assert len(logs) == 1
        entry = logs[0]

        # Verify all expected fields are present
        assert entry["log_id"] == log_id
        assert entry["question_id"] == "2024-12-set1-writing-writing-01"
        assert entry["model"] == "deepseek-v4-flash"
        assert entry["http_status"] == 200
        assert entry["duration_ms"] == 1500
        assert entry["prompt_tokens"] == 800
        assert entry["completion_tokens"] == 512
        assert entry["from_cache"] is False
        assert entry["context_truncated"] is True

        # Verify no forbidden fields leak through the dict
        for forbidden in _FORBIDDEN_FIELDS:
            assert forbidden not in entry

    def test_grading_log_cache_hit_entry(self, log_repo: LogRepo):
        """A cache-hit log entry has http_status=None and from_cache=True."""
        log_repo.insert_grading_log(
            question_id="q-cache-hit",
            model="deepseek-v4-flash",
            http_status=None,
            duration_ms=None,
            prompt_tokens=None,
            completion_tokens=None,
            from_cache=True,
            context_truncated=False,
        )

        logs = log_repo.query_grading_logs(question_id="q-cache-hit")
        assert len(logs) == 1
        assert logs[0]["from_cache"] is True
        assert logs[0]["http_status"] is None


# ======================================================================
# 5. 30-day log cleanup: logs older than 30 days are removed — Req 14.5
# ======================================================================


class TestLogCleanup30Days:
    """Logs older than 30 days are removed by cleanup_old_logs."""

    def test_cleanup_removes_old_app_logs(self, log_repo: LogRepo, engine):
        """app_log entries older than 30 days are deleted."""
        # Insert an old log entry (35 days ago) directly via SQL
        old_time = (datetime.now(timezone.utc) - timedelta(days=35)).isoformat()
        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO app_log (log_id, level, category, message, created_at) "
                    "VALUES (:id, :level, :cat, :msg, :ts)"
                ),
                {"id": "old-log-1", "level": "ERROR", "cat": "ai", "msg": "old error", "ts": old_time},
            )

        # Insert a recent log entry (5 days ago)
        recent_time = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO app_log (log_id, level, category, message, created_at) "
                    "VALUES (:id, :level, :cat, :msg, :ts)"
                ),
                {"id": "recent-log-1", "level": "INFO", "cat": "ai", "msg": "recent info", "ts": recent_time},
            )

        # Run cleanup
        deleted = log_repo.cleanup_old_logs(days=30)
        assert deleted >= 1

        # Verify old log is gone, recent log remains
        logs = log_repo.query_logs()
        log_ids = [log["log_id"] for log in logs]
        assert "old-log-1" not in log_ids
        assert "recent-log-1" in log_ids

    def test_cleanup_removes_old_grading_logs(self, log_repo: LogRepo, engine):
        """ai_grading_log entries older than 30 days are deleted."""
        # Insert an old grading log entry (40 days ago) directly via SQL
        old_time = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO ai_grading_log "
                    "(log_id, question_id, model, http_status, duration_ms, "
                    "prompt_tokens, completion_tokens, from_cache, context_truncated, created_at) "
                    "VALUES (:id, :qid, :model, :status, :dur, :pt, :ct, :fc, :trunc, :ts)"
                ),
                {
                    "id": "old-grading-1",
                    "qid": "q-old",
                    "model": "deepseek-v4-flash",
                    "status": 200,
                    "dur": 1000,
                    "pt": 500,
                    "ct": 300,
                    "fc": 0,
                    "trunc": 0,
                    "ts": old_time,
                },
            )

        # Insert a recent grading log entry (10 days ago)
        recent_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO ai_grading_log "
                    "(log_id, question_id, model, http_status, duration_ms, "
                    "prompt_tokens, completion_tokens, from_cache, context_truncated, created_at) "
                    "VALUES (:id, :qid, :model, :status, :dur, :pt, :ct, :fc, :trunc, :ts)"
                ),
                {
                    "id": "recent-grading-1",
                    "qid": "q-recent",
                    "model": "deepseek-v4-flash",
                    "status": 200,
                    "dur": 800,
                    "pt": 400,
                    "ct": 200,
                    "fc": 0,
                    "trunc": 0,
                    "ts": recent_time,
                },
            )

        # Run cleanup
        deleted = log_repo.cleanup_old_logs(days=30)
        assert deleted >= 1

        # Verify old grading log is gone, recent one remains
        logs = log_repo.query_grading_logs()
        log_ids = [log["log_id"] for log in logs]
        assert "old-grading-1" not in log_ids
        assert "recent-grading-1" in log_ids

    def test_cleanup_retains_logs_within_30_days(self, log_repo: LogRepo):
        """Logs within 30 days are NOT removed by cleanup."""
        # Insert logs at various recent ages
        log_repo.insert_log("INFO", "day 1 log", "test")
        log_repo.insert_log("WARN", "day 2 log", "test")
        log_repo.insert_grading_log(
            question_id="q-recent-test",
            model="deepseek-v4-flash",
            http_status=200,
            duration_ms=500,
        )

        # Run cleanup — nothing should be deleted since all are fresh
        deleted = log_repo.cleanup_old_logs(days=30)
        assert deleted == 0

        # All logs still present
        app_logs = log_repo.query_logs()
        assert len(app_logs) >= 2

        grading_logs = log_repo.query_grading_logs()
        assert len(grading_logs) >= 1

    def test_cleanup_both_tables_simultaneously(self, log_repo: LogRepo, engine):
        """cleanup_old_logs removes old entries from BOTH tables in one call."""
        old_time = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()

        with transaction(engine) as conn:
            # Old app_log
            conn.execute(
                text(
                    "INSERT INTO app_log (log_id, level, category, message, created_at) "
                    "VALUES (:id, :level, :cat, :msg, :ts)"
                ),
                {"id": "old-app-both", "level": "ERROR", "cat": "persist", "msg": "old", "ts": old_time},
            )
            # Old ai_grading_log
            conn.execute(
                text(
                    "INSERT INTO ai_grading_log "
                    "(log_id, question_id, model, http_status, duration_ms, "
                    "prompt_tokens, completion_tokens, from_cache, context_truncated, created_at) "
                    "VALUES (:id, :qid, :model, :status, :dur, :pt, :ct, :fc, :trunc, :ts)"
                ),
                {
                    "id": "old-ai-both",
                    "qid": "q-both",
                    "model": "deepseek-v4-flash",
                    "status": 500,
                    "dur": 2000,
                    "pt": 600,
                    "ct": 0,
                    "fc": 0,
                    "trunc": 0,
                    "ts": old_time,
                },
            )

        deleted = log_repo.cleanup_old_logs(days=30)
        assert deleted == 2

        # Both are gone
        app_logs = log_repo.query_logs()
        assert all(log["log_id"] != "old-app-both" for log in app_logs)

        grading_logs = log_repo.query_grading_logs()
        assert all(log["log_id"] != "old-ai-both" for log in grading_logs)
