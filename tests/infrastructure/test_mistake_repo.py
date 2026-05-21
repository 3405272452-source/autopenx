"""Tests for MistakeRepo — CRUD, filtering, sorting, and bulk import.

Requirements: 9.4 (multi-condition filtering), 12.1 (persistence).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.infrastructure.persistence.db import create_engine, init_schema, transaction
from cet4_app.infrastructure.repositories.mistake_repo import MistakeQuery, MistakeRepo


@pytest.fixture
def engine(tmp_path: Path):
    """Create a temporary SQLite engine with schema initialized."""
    db_path = tmp_path / "test.db"
    eng = create_engine(db_path)
    init_schema(eng)
    return eng


@pytest.fixture
def repo(engine):
    """Create a MistakeRepo instance."""
    return MistakeRepo(engine)


@pytest.fixture
def seed_question(engine):
    """Insert a minimal question + paper_set + paper row for FK satisfaction."""

    def _seed(
        question_id: str = "q1",
        paper_id: str = "p1",
        paper_set_id: str = "ps1",
        question_type: str = "reading_careful_choice",
    ):
        with transaction(engine) as conn:
            # paper_set
            conn.execute(
                text(
                    """
                    INSERT OR IGNORE INTO paper_set (paper_set_id, exam_period, directory_name, scanned_at)
                    VALUES (:ps_id, '2024-12', 'dir1', :now)
                    """
                ),
                {"ps_id": paper_set_id, "now": datetime.now().isoformat()},
            )
            # paper
            conn.execute(
                text(
                    """
                    INSERT OR IGNORE INTO paper (
                        paper_id, paper_set_id, set_index,
                        audio_status, status, updated_at
                    ) VALUES (:p_id, :ps_id, 1, 'available', 'ok', :now)
                    """
                ),
                {"p_id": paper_id, "ps_id": paper_set_id, "now": datetime.now().isoformat()},
            )
            # question
            conn.execute(
                text(
                    """
                    INSERT OR IGNORE INTO question (
                        question_id, paper_id, section, question_type,
                        prompt, score
                    ) VALUES (:q_id, :p_id, 'reading', :qt, 'test prompt', 3.55)
                    """
                ),
                {"q_id": question_id, "p_id": paper_id, "qt": question_type},
            )

    return _seed


def _make_entry(
    entry_id: str = "e1",
    question_id: str = "q1",
    paper_id: str = "p1",
    error_count: int = 1,
    redo_count: int = 0,
    correct_streak: int = 0,
    mastered: bool = False,
    notes: str = "",
    tags: list[str] | None = None,
    first_wrong_at: datetime | None = None,
    last_wrong_at: datetime | None = None,
) -> MistakeEntry:
    now = datetime.now()
    return MistakeEntry(
        entry_id=entry_id,
        question_id=question_id,
        paper_id=paper_id,
        first_wrong_at=first_wrong_at or now,
        last_wrong_at=last_wrong_at or now,
        error_count=error_count,
        redo_count=redo_count,
        correct_streak=correct_streak,
        mastered=mastered,
        notes=notes,
        tags=tags or [],
    )


# ===========================================================================
# Basic CRUD
# ===========================================================================


class TestSaveAndLoad:
    def test_save_and_load_by_id(self, repo, seed_question):
        seed_question()
        entry = _make_entry(tags=["grammar", "hard"])
        repo.save_entry(entry)

        loaded = repo.load_by_id("e1")
        assert loaded is not None
        assert loaded.entry_id == "e1"
        assert loaded.question_id == "q1"
        assert loaded.tags == ["grammar", "hard"]

    def test_load_by_question_id(self, repo, seed_question):
        seed_question()
        entry = _make_entry()
        repo.save_entry(entry)

        loaded = repo.load_by_question_id("q1")
        assert loaded is not None
        assert loaded.entry_id == "e1"

    def test_load_by_id_not_found(self, repo):
        assert repo.load_by_id("nonexistent") is None

    def test_load_by_question_id_not_found(self, repo):
        assert repo.load_by_question_id("nonexistent") is None


class TestUpdate:
    def test_update_entry(self, repo, seed_question):
        seed_question()
        entry = _make_entry(error_count=1, notes="first")
        repo.save_entry(entry)

        updated = _make_entry(error_count=3, notes="updated note")
        repo.update_entry(updated)

        loaded = repo.load_by_id("e1")
        assert loaded is not None
        assert loaded.error_count == 3
        assert loaded.notes == "updated note"

    def test_update_nonexistent_raises(self, repo):
        entry = _make_entry(entry_id="ghost")
        with pytest.raises(ValueError, match="not found"):
            repo.update_entry(entry)


class TestDelete:
    def test_delete_existing(self, repo, seed_question):
        seed_question()
        repo.save_entry(_make_entry())
        assert repo.delete_entry("e1") is True
        assert repo.load_by_id("e1") is None

    def test_delete_nonexistent(self, repo):
        assert repo.delete_entry("ghost") is False


# ===========================================================================
# Filtering
# ===========================================================================


class TestFilterEntries:
    def test_filter_by_error_count_range(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")
        seed_question(question_id="q3")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", error_count=1))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2", error_count=5))
        repo.save_entry(_make_entry(entry_id="e3", question_id="q3", error_count=10))

        results = repo.filter_entries(MistakeQuery(error_count_min=3, error_count_max=7))
        assert len(results) == 1
        assert results[0].entry_id == "e2"

    def test_filter_by_last_wrong_at_range(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        now = datetime.now()
        old = now - timedelta(days=10)
        recent = now - timedelta(days=1)

        repo.save_entry(
            _make_entry(entry_id="e1", question_id="q1", first_wrong_at=old, last_wrong_at=old)
        )
        repo.save_entry(
            _make_entry(
                entry_id="e2", question_id="q2", first_wrong_at=recent, last_wrong_at=recent
            )
        )

        cutoff = now - timedelta(days=5)
        results = repo.filter_entries(MistakeQuery(last_wrong_at_start=cutoff))
        assert len(results) == 1
        assert results[0].entry_id == "e2"

    def test_filter_by_tag(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", tags=["hard", "grammar"]))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2", tags=["easy", "vocabulary"]))

        results = repo.filter_entries(MistakeQuery(any_tag="grammar"))
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    def test_filter_by_difficulty_tag(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", tags=["hard"]))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2", tags=["easy"]))

        results = repo.filter_entries(MistakeQuery(difficulty_tag="hard"))
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    def test_filter_by_question_type(self, repo, seed_question):
        seed_question(question_id="q1", question_type="reading_careful_choice")
        seed_question(question_id="q2", question_type="listening_news")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1"))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2"))

        results = repo.filter_entries(MistakeQuery(question_type="listening_news"))
        assert len(results) == 1
        assert results[0].entry_id == "e2"

    def test_filter_by_paper_set(self, repo, seed_question):
        seed_question(question_id="q1", paper_id="p1", paper_set_id="ps1")
        seed_question(question_id="q2", paper_id="p2", paper_set_id="ps2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", paper_id="p1"))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2", paper_id="p2"))

        results = repo.filter_entries(MistakeQuery(paper_set="ps2"))
        assert len(results) == 1
        assert results[0].entry_id == "e2"

    def test_filter_by_mastered(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", mastered=False))
        repo.save_entry(
            _make_entry(
                entry_id="e2", question_id="q2", mastered=True, correct_streak=2
            )
        )

        results = repo.filter_entries(MistakeQuery(mastered=False))
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    def test_combined_filters(self, repo, seed_question):
        """Multiple conditions combined with AND (Req 9.4)."""
        seed_question(question_id="q1")
        seed_question(question_id="q2")
        seed_question(question_id="q3")

        repo.save_entry(
            _make_entry(entry_id="e1", question_id="q1", error_count=5, tags=["hard"])
        )
        repo.save_entry(
            _make_entry(entry_id="e2", question_id="q2", error_count=2, tags=["hard"])
        )
        repo.save_entry(
            _make_entry(entry_id="e3", question_id="q3", error_count=5, tags=["easy"])
        )

        results = repo.filter_entries(
            MistakeQuery(error_count_min=4, any_tag="hard")
        )
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    def test_empty_filter_returns_all(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1"))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2"))

        results = repo.filter_entries(MistakeQuery())
        assert len(results) == 2


# ===========================================================================
# Sorting
# ===========================================================================


class TestSorting:
    def test_sort_by_error_count_desc(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")
        seed_question(question_id="q3")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", error_count=3))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2", error_count=10))
        repo.save_entry(_make_entry(entry_id="e3", question_id="q3", error_count=1))

        results = repo.filter_entries(
            MistakeQuery(sort_by="error_count", sort_order="desc")
        )
        assert [r.error_count for r in results] == [10, 3, 1]

    def test_sort_by_error_count_asc(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", error_count=5))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2", error_count=2))

        results = repo.filter_entries(
            MistakeQuery(sort_by="error_count", sort_order="asc")
        )
        assert [r.error_count for r in results] == [2, 5]

    def test_sort_by_redo_count(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1", redo_count=0))
        repo.save_entry(_make_entry(entry_id="e2", question_id="q2", redo_count=7))

        results = repo.filter_entries(
            MistakeQuery(sort_by="redo_count", sort_order="desc")
        )
        assert results[0].redo_count == 7

    def test_sort_by_first_wrong_at(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        now = datetime.now()
        earlier = now - timedelta(days=5)

        repo.save_entry(
            _make_entry(entry_id="e1", question_id="q1", first_wrong_at=now, last_wrong_at=now)
        )
        repo.save_entry(
            _make_entry(
                entry_id="e2", question_id="q2", first_wrong_at=earlier, last_wrong_at=earlier
            )
        )

        results = repo.filter_entries(
            MistakeQuery(sort_by="first_wrong_at", sort_order="asc")
        )
        assert results[0].entry_id == "e2"


# ===========================================================================
# Pagination
# ===========================================================================


class TestPagination:
    def test_limit(self, repo, seed_question):
        for i in range(5):
            seed_question(question_id=f"q{i}")
            repo.save_entry(_make_entry(entry_id=f"e{i}", question_id=f"q{i}", error_count=i + 1))

        results = repo.filter_entries(
            MistakeQuery(sort_by="error_count", sort_order="asc", limit=3)
        )
        assert len(results) == 3

    def test_offset(self, repo, seed_question):
        for i in range(5):
            seed_question(question_id=f"q{i}")
            repo.save_entry(_make_entry(entry_id=f"e{i}", question_id=f"q{i}", error_count=i + 1))

        results = repo.filter_entries(
            MistakeQuery(sort_by="error_count", sort_order="asc", limit=2, offset=2)
        )
        assert len(results) == 2
        assert results[0].error_count == 3


# ===========================================================================
# Bulk Import
# ===========================================================================


class TestBulkImport:
    def test_bulk_import_inserts_all(self, repo, seed_question):
        for i in range(3):
            seed_question(question_id=f"q{i}")

        entries = [_make_entry(entry_id=f"e{i}", question_id=f"q{i}") for i in range(3)]
        count = repo.bulk_import(entries)
        assert count == 3

    def test_bulk_import_skips_duplicates(self, repo, seed_question):
        seed_question(question_id="q1")
        seed_question(question_id="q2")

        repo.save_entry(_make_entry(entry_id="e1", question_id="q1"))

        entries = [
            _make_entry(entry_id="e1_dup", question_id="q1"),  # duplicate question_id
            _make_entry(entry_id="e2", question_id="q2"),  # new
        ]
        count = repo.bulk_import(entries)
        assert count == 1

    def test_bulk_import_empty_list(self, repo):
        assert repo.bulk_import([]) == 0


# ===========================================================================
# JSON field handling
# ===========================================================================


class TestJsonFields:
    def test_tags_round_trip(self, repo, seed_question):
        seed_question()
        tags = ["grammar", "cet4_core", "hard"]
        entry = _make_entry(tags=tags)
        repo.save_entry(entry)

        loaded = repo.load_by_id("e1")
        assert loaded is not None
        assert loaded.tags == tags

    def test_empty_tags(self, repo, seed_question):
        seed_question()
        entry = _make_entry(tags=[])
        repo.save_entry(entry)

        loaded = repo.load_by_id("e1")
        assert loaded is not None
        assert loaded.tags == []

    def test_unicode_notes(self, repo, seed_question):
        seed_question()
        entry = _make_entry(notes="这是一个中文备注 with English")
        repo.save_entry(entry)

        loaded = repo.load_by_id("e1")
        assert loaded is not None
        assert loaded.notes == "这是一个中文备注 with English"
