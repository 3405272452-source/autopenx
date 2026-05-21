"""Unit tests for MistakeService application service.

Tests cover:
- Query and filter mistakes (Req 9.4)
- Redo session creation (Req 9.5)
- Export mistakes to JSON (Req 9.7)
- Import mistakes from JSON with validation and ID conflict rejection (Req 9.10)

Uses a temporary SQLite database for each test to ensure isolation.

Requirements: 9.4, 9.5, 9.7, 9.10
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from cet4_app.application.mistake_service import (
    MistakeImportReport,
    MistakeService,
)
from cet4_app.domain.enums import SessionMode, SheetStatus
from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.infrastructure.persistence.db import init_schema
from cet4_app.infrastructure.repositories.mistake_repo import MistakeQuery, MistakeRepo


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    """Create a fresh SQLite engine with schema initialized.

    FK checks are disabled for this test module because we are testing
    the application service logic, not the DB referential integrity.
    The mistake_entry table has FKs to paper and question tables which
    would require complex setup unrelated to the service under test.
    """
    import sqlalchemy
    from sqlalchemy import event, text as sa_text

    db_path = tmp_path / "test_mistake_service.db"
    # Create engine without the default FK=ON pragma from db.py
    eng = sqlalchemy.create_engine(f"sqlite:///{db_path}", echo=False)

    @event.listens_for(eng, "connect")
    def _set_pragmas(dbapi_connection, connection_record):  # noqa: ARG001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.close()

    init_schema(eng)
    return eng


@pytest.fixture
def mistake_repo(engine: Engine) -> MistakeRepo:
    return MistakeRepo(engine)


@pytest.fixture
def service(mistake_repo: MistakeRepo) -> MistakeService:
    return MistakeService(mistake_repo)


def _make_entry(
    entry_id: str = "entry001",
    question_id: str = "q001",
    paper_id: str = "paper001",
    error_count: int = 1,
    mastered: bool = False,
    correct_streak: int = 0,
    tags: list[str] | None = None,
) -> MistakeEntry:
    """Helper to create a valid MistakeEntry for testing."""
    now = datetime.now(timezone.utc)
    return MistakeEntry(
        entry_id=entry_id,
        question_id=question_id,
        paper_id=paper_id,
        first_wrong_at=now - timedelta(days=1),
        last_wrong_at=now,
        error_count=error_count,
        redo_count=0,
        correct_streak=correct_streak,
        mastered=mastered,
        notes="",
        tags=tags or [],
    )


# ===========================================================================
# Query & Filter Tests (Req 9.4)
# ===========================================================================


class TestQueryMistakes:
    """Tests for MistakeService.query_mistakes."""

    def test_query_returns_all_when_no_filter(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Empty query returns all entries."""
        e1 = _make_entry(entry_id="e1", question_id="q1")
        e2 = _make_entry(entry_id="e2", question_id="q2")
        mistake_repo.save_entry(e1)
        mistake_repo.save_entry(e2)

        results = service.query_mistakes(MistakeQuery())
        assert len(results) == 2

    def test_query_filter_by_mastered(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Filter by mastered status works."""
        e1 = _make_entry(entry_id="e1", question_id="q1", mastered=False)
        e2 = _make_entry(
            entry_id="e2", question_id="q2", mastered=True, correct_streak=2
        )
        mistake_repo.save_entry(e1)
        mistake_repo.save_entry(e2)

        results = service.query_mistakes(MistakeQuery(mastered=True))
        assert len(results) == 1
        assert results[0].entry_id == "e2"

    def test_query_filter_by_error_count_range(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Filter by error_count range works."""
        e1 = _make_entry(entry_id="e1", question_id="q1", error_count=1)
        e2 = _make_entry(entry_id="e2", question_id="q2", error_count=5)
        e3 = _make_entry(entry_id="e3", question_id="q3", error_count=10)
        mistake_repo.save_entry(e1)
        mistake_repo.save_entry(e2)
        mistake_repo.save_entry(e3)

        results = service.query_mistakes(
            MistakeQuery(error_count_min=3, error_count_max=7)
        )
        assert len(results) == 1
        assert results[0].entry_id == "e2"

    def test_query_filter_by_tag(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Filter by tag works."""
        e1 = _make_entry(entry_id="e1", question_id="q1", tags=["grammar"])
        e2 = _make_entry(entry_id="e2", question_id="q2", tags=["vocabulary"])
        mistake_repo.save_entry(e1)
        mistake_repo.save_entry(e2)

        results = service.query_mistakes(MistakeQuery(any_tag="grammar"))
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    def test_query_multiple_filters_combined(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Multiple filter conditions are combined with AND logic."""
        e1 = _make_entry(
            entry_id="e1", question_id="q1", error_count=3, tags=["grammar"]
        )
        e2 = _make_entry(
            entry_id="e2", question_id="q2", error_count=1, tags=["grammar"]
        )
        e3 = _make_entry(
            entry_id="e3", question_id="q3", error_count=3, tags=["vocabulary"]
        )
        mistake_repo.save_entry(e1)
        mistake_repo.save_entry(e2)
        mistake_repo.save_entry(e3)

        results = service.query_mistakes(
            MistakeQuery(error_count_min=2, any_tag="grammar")
        )
        assert len(results) == 1
        assert results[0].entry_id == "e1"


# ===========================================================================
# Redo Session Tests (Req 9.5)
# ===========================================================================


class TestRedoSession:
    """Tests for MistakeService.create_redo_session and record_redo_result."""

    def test_create_redo_session_returns_single_question_sheet(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """create_redo_session returns an in-progress AnswerSheet."""
        entry = _make_entry(entry_id="e1", question_id="q1", paper_id="paper1")
        mistake_repo.save_entry(entry)

        sheet = service.create_redo_session("e1")
        assert sheet.status == SheetStatus.in_progress
        assert sheet.mode == SessionMode.practice
        assert sheet.paper_id == "paper1"
        assert sheet.elapsed_seconds == 0
        assert sheet.answers == {}

    def test_create_redo_session_raises_on_missing_entry(
        self, service: MistakeService
    ):
        """create_redo_session raises ValueError for non-existent entry."""
        with pytest.raises(ValueError, match="not found"):
            service.create_redo_session("nonexistent")

    def test_record_redo_result_correct_increments_streak(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """record_redo_result with correct=True increments correct_streak."""
        entry = _make_entry(entry_id="e1", question_id="q1")
        mistake_repo.save_entry(entry)

        updated = service.record_redo_result("e1", correct=True)
        assert updated.redo_count == 1
        assert updated.correct_streak == 1
        assert updated.mastered is False

    def test_record_redo_result_two_correct_marks_mastered(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Two consecutive correct redos mark the entry as mastered (Req 9.6)."""
        entry = _make_entry(entry_id="e1", question_id="q1")
        mistake_repo.save_entry(entry)

        service.record_redo_result("e1", correct=True)
        updated = service.record_redo_result("e1", correct=True)
        assert updated.redo_count == 2
        assert updated.correct_streak == 2
        assert updated.mastered is True

    def test_record_redo_result_incorrect_resets_streak(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """record_redo_result with correct=False resets streak (Req 9.9)."""
        entry = _make_entry(entry_id="e1", question_id="q1")
        mistake_repo.save_entry(entry)

        service.record_redo_result("e1", correct=True)
        updated = service.record_redo_result("e1", correct=False)
        assert updated.correct_streak == 0
        assert updated.mastered is False

    def test_record_redo_result_raises_on_missing_entry(
        self, service: MistakeService
    ):
        """record_redo_result raises ValueError for non-existent entry."""
        with pytest.raises(ValueError, match="not found"):
            service.record_redo_result("nonexistent", correct=True)


# ===========================================================================
# Export Tests (Req 9.7)
# ===========================================================================


class TestExportMistakes:
    """Tests for MistakeService.export_mistakes_json."""

    def test_export_empty_returns_empty_array(self, service: MistakeService):
        """Export with no entries returns an empty JSON array."""
        result = service.export_mistakes_json()
        data = json.loads(result)
        assert data == []

    def test_export_returns_all_entries(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Export returns all entries as JSON."""
        e1 = _make_entry(entry_id="e1", question_id="q1")
        e2 = _make_entry(entry_id="e2", question_id="q2")
        mistake_repo.save_entry(e1)
        mistake_repo.save_entry(e2)

        result = service.export_mistakes_json()
        data = json.loads(result)
        assert len(data) == 2

    def test_export_round_trip_with_import(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Exported JSON can be imported back successfully (Req 9.7)."""
        entry = _make_entry(entry_id="e1", question_id="q1", tags=["grammar"])
        mistake_repo.save_entry(entry)

        exported = service.export_mistakes_json()

        # Clear the database
        mistake_repo.delete_entry("e1")

        # Import back
        report = service.import_mistakes_json(exported)
        assert report.success is True
        assert report.imported_count == 1

        # Verify the entry is back
        loaded = mistake_repo.load_by_id("e1")
        assert loaded is not None
        assert loaded.question_id == "q1"
        assert loaded.tags == ["grammar"]


# ===========================================================================
# Import Tests (Req 9.10)
# ===========================================================================


class TestImportMistakes:
    """Tests for MistakeService.import_mistakes_json."""

    def test_import_valid_entries(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Valid entries are imported successfully."""
        now = datetime.now(timezone.utc)
        entries_data = [
            {
                "entry_id": "e1",
                "question_id": "q1",
                "paper_id": "p1",
                "first_wrong_at": (now - timedelta(days=1)).isoformat(),
                "last_wrong_at": now.isoformat(),
                "error_count": 1,
                "redo_count": 0,
                "correct_streak": 0,
                "mastered": False,
                "notes": "",
                "tags": [],
            }
        ]
        json_str = json.dumps(entries_data)
        report = service.import_mistakes_json(json_str)

        assert report.success is True
        assert report.imported_count == 1
        assert mistake_repo.load_by_id("e1") is not None

    def test_import_rejects_invalid_json(self, service: MistakeService):
        """Invalid JSON string is rejected."""
        report = service.import_mistakes_json("not valid json {{{")
        assert report.success is False
        assert "JSON 格式无效" in report.error_message

    def test_import_rejects_non_array(self, service: MistakeService):
        """Non-array top-level structure is rejected."""
        report = service.import_mistakes_json('{"key": "value"}')
        assert report.success is False
        assert "数组" in report.error_message

    def test_import_rejects_invalid_entry_structure(self, service: MistakeService):
        """Entries with missing required fields are rejected."""
        entries_data = [
            {
                "entry_id": "e1",
                # Missing required fields
            }
        ]
        json_str = json.dumps(entries_data)
        report = service.import_mistakes_json(json_str)

        assert report.success is False
        assert len(report.failures) > 0

    def test_import_rejects_internal_duplicate_entry_id(
        self, service: MistakeService
    ):
        """Duplicate entry_id within import data is rejected."""
        now = datetime.now(timezone.utc)
        base = {
            "paper_id": "p1",
            "first_wrong_at": (now - timedelta(days=1)).isoformat(),
            "last_wrong_at": now.isoformat(),
            "error_count": 1,
            "redo_count": 0,
            "correct_streak": 0,
            "mastered": False,
            "notes": "",
            "tags": [],
        }
        entries_data = [
            {**base, "entry_id": "e1", "question_id": "q1"},
            {**base, "entry_id": "e1", "question_id": "q2"},  # duplicate entry_id
        ]
        json_str = json.dumps(entries_data)
        report = service.import_mistakes_json(json_str)

        assert report.success is False
        assert any("entry_id" in f.field_path for f in report.failures)
        assert any("e1" in f.reason for f in report.failures)

    def test_import_rejects_internal_duplicate_question_id(
        self, service: MistakeService
    ):
        """Duplicate question_id within import data is rejected."""
        now = datetime.now(timezone.utc)
        base = {
            "paper_id": "p1",
            "first_wrong_at": (now - timedelta(days=1)).isoformat(),
            "last_wrong_at": now.isoformat(),
            "error_count": 1,
            "redo_count": 0,
            "correct_streak": 0,
            "mastered": False,
            "notes": "",
            "tags": [],
        }
        entries_data = [
            {**base, "entry_id": "e1", "question_id": "q1"},
            {**base, "entry_id": "e2", "question_id": "q1"},  # duplicate question_id
        ]
        json_str = json.dumps(entries_data)
        report = service.import_mistakes_json(json_str)

        assert report.success is False
        assert any("question_id" in f.field_path for f in report.failures)

    def test_import_rejects_conflict_with_existing_entry_id(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Import is rejected when entry_id conflicts with existing data (Req 9.10)."""
        # Pre-populate an entry
        existing = _make_entry(entry_id="e1", question_id="q_existing")
        mistake_repo.save_entry(existing)

        # Try to import with same entry_id
        now = datetime.now(timezone.utc)
        entries_data = [
            {
                "entry_id": "e1",  # conflicts with existing
                "question_id": "q_new",
                "paper_id": "p1",
                "first_wrong_at": (now - timedelta(days=1)).isoformat(),
                "last_wrong_at": now.isoformat(),
                "error_count": 1,
                "redo_count": 0,
                "correct_streak": 0,
                "mastered": False,
                "notes": "",
                "tags": [],
            }
        ]
        json_str = json.dumps(entries_data)
        report = service.import_mistakes_json(json_str)

        assert report.success is False
        assert any("entry_id" in f.field_path for f in report.failures)
        assert any("已存在" in f.reason for f in report.failures)

    def test_import_rejects_conflict_with_existing_question_id(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """Import is rejected when question_id conflicts with existing data (Req 9.10)."""
        # Pre-populate an entry
        existing = _make_entry(entry_id="e_existing", question_id="q1")
        mistake_repo.save_entry(existing)

        # Try to import with same question_id
        now = datetime.now(timezone.utc)
        entries_data = [
            {
                "entry_id": "e_new",
                "question_id": "q1",  # conflicts with existing
                "paper_id": "p1",
                "first_wrong_at": (now - timedelta(days=1)).isoformat(),
                "last_wrong_at": now.isoformat(),
                "error_count": 1,
                "redo_count": 0,
                "correct_streak": 0,
                "mastered": False,
                "notes": "",
                "tags": [],
            }
        ]
        json_str = json.dumps(entries_data)
        report = service.import_mistakes_json(json_str)

        assert report.success is False
        assert any("question_id" in f.field_path for f in report.failures)
        assert any("已存在" in f.reason for f in report.failures)

    def test_import_preserves_existing_data_on_failure(
        self, service: MistakeService, mistake_repo: MistakeRepo
    ):
        """On import failure, existing data is preserved unchanged (Req 9.10)."""
        # Pre-populate
        existing = _make_entry(entry_id="e_existing", question_id="q_existing")
        mistake_repo.save_entry(existing)

        # Try to import invalid data
        report = service.import_mistakes_json("[{invalid}]")
        assert report.success is False

        # Existing data should still be there
        loaded = mistake_repo.load_by_id("e_existing")
        assert loaded is not None
        assert loaded.question_id == "q_existing"

    def test_import_empty_array_succeeds(self, service: MistakeService):
        """Importing an empty array succeeds with 0 count."""
        report = service.import_mistakes_json("[]")
        assert report.success is True
        assert report.imported_count == 0

    def test_import_reports_all_validation_failures(
        self, service: MistakeService
    ):
        """All validation failures are reported, not just the first one."""
        entries_data = [
            {"entry_id": "e1"},  # Missing many fields
            {"entry_id": "e2"},  # Missing many fields
        ]
        json_str = json.dumps(entries_data)
        report = service.import_mistakes_json(json_str)

        assert report.success is False
        # Should have failures for both entries
        indices = {f.index for f in report.failures}
        assert 0 in indices
        assert 1 in indices
