"""Unit tests for the backup importer module.

Tests cover:
- Empty import (all categories empty)
- Valid import with real data
- Validation rejection (invalid fields)
- ID conflict rejection (Req 9.10)
- Atomic rollback on DB failure
- Non-dict top-level rejection
- Non-list category rejection
"""

from __future__ import annotations

import json
import tempfile
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from cet4_app.domain.enums import (
    DayStatus,
    SectionName,
    SessionMode,
    SheetStatus,
    TaskKind,
)
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet
from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.domain.models.score_report import QuestionGrade, ScoreReport
from cet4_app.domain.models.study_plan import (
    PlanParams,
    StudyDay,
    StudyPlan,
    StudyTask,
)
from cet4_app.infrastructure.persistence.backup.importer import (
    BackupImporter,
    ImportReport,
    ValidationFailure,
)
from cet4_app.infrastructure.persistence.db import create_engine, init_schema


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    """Create a fresh SQLite engine with schema initialized."""
    db_path = tmp_path / "test.db"
    eng = create_engine(db_path)
    init_schema(eng)
    return eng


@pytest.fixture
def importer(engine: Engine) -> BackupImporter:
    """Create a BackupImporter instance."""
    return BackupImporter(engine)


def _make_answer_sheet_dict() -> dict:
    """Create a valid AnswerSheet dict for testing."""
    now = datetime.now(timezone.utc)
    return {
        "sheet_id": "sheet-001",
        "paper_id": "paper-001",
        "status": "submitted",
        "mode": "practice",
        "started_at": (now - timedelta(hours=2)).isoformat(),
        "submitted_at": now.isoformat(),
        "elapsed_seconds": 3600,
        "mock_deadline": None,
        "draft_saved_at": (now - timedelta(minutes=5)).isoformat(),
        "updated_at": now.isoformat(),
        "answers": {},
    }


def _make_score_report_dict() -> dict:
    """Create a valid ScoreReport dict for testing."""
    now = datetime.now(timezone.utc)
    return {
        "report_id": "report-001",
        "sheet_id": "sheet-001",
        "paper_id": "paper-001",
        "total_score": "75.50",
        "scaled_score_710": 500,
        "section_scores": {"writing": "15.00", "listening": "20.00", "reading": "25.50", "translation": "15.00"},
        "grades": [
            {
                "question_id": "q-001",
                "is_correct": True,
                "status": "ok",
                "earned_score": "3.55",
                "score_max": "3.55",
                "reference_answer": "A",
                "user_answer": "A",
                "explanation_summary": "",
            }
        ],
        "correct_count": 1,
        "wrong_count": 0,
        "unanswered_count": 0,
        "cannot_grade_ids": [],
        "duration_seconds": 3600,
        "generated_at": now.isoformat(),
    }


def _make_mistake_entry_dict() -> dict:
    """Create a valid MistakeEntry dict for testing."""
    now = datetime.now(timezone.utc)
    return {
        "entry_id": "mistake-001",
        "question_id": "q-002",
        "paper_id": "paper-001",
        "first_wrong_at": (now - timedelta(days=3)).isoformat(),
        "last_wrong_at": now.isoformat(),
        "error_count": 2,
        "redo_count": 1,
        "correct_streak": 0,
        "mastered": False,
        "notes": "需要复习语法",
        "tags": ["grammar"],
    }


def _make_study_plan_dict() -> dict:
    """Create a valid StudyPlan dict for testing."""
    start = date.today()
    days = []
    for i in range(20):
        days.append({
            "day_index": i + 1,
            "date": (start + timedelta(days=i)).isoformat(),
            "tasks": [],
            "status": "pending",
            "daily_target_accuracy": None,
        })

    return {
        "plan_id": "plan-001",
        "start_date": start.isoformat(),
        "total_days": 20,
        "params": {
            "start_date": start.isoformat(),
            "daily_minutes_cap": 120,
            "section_ratio": {
                "writing": 25,
                "listening": 25,
                "reading": 25,
                "translation": 25,
            },
            "daily_target_accuracy": None,
        },
        "days": days,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEmptyImport:
    """Test importing with empty data."""

    def test_empty_dict_succeeds(self, importer: BackupImporter) -> None:
        report = importer.import_from_dict({})
        assert report.success is True
        assert report.answer_sheets_count == 0
        assert report.score_reports_count == 0
        assert report.mistake_entries_count == 0
        assert report.study_plans_count == 0
        assert report.validation_errors == []

    def test_empty_lists_succeeds(self, importer: BackupImporter) -> None:
        data = {
            "answer_sheets": [],
            "score_reports": [],
            "mistake_entries": [],
            "study_plans": [],
        }
        report = importer.import_from_dict(data)
        assert report.success is True
        assert report.answer_sheets_count == 0


class TestValidImport:
    """Test importing valid data."""

    def test_import_answer_sheet(self, importer: BackupImporter) -> None:
        data = {"answer_sheets": [_make_answer_sheet_dict()]}
        report = importer.import_from_dict(data)
        assert report.success is True
        assert report.answer_sheets_count == 1

    def test_import_mistake_entry(self, importer: BackupImporter) -> None:
        data = {"mistake_entries": [_make_mistake_entry_dict()]}
        report = importer.import_from_dict(data)
        assert report.success is True
        assert report.mistake_entries_count == 1

    def test_import_study_plan(self, importer: BackupImporter) -> None:
        data = {"study_plans": [_make_study_plan_dict()]}
        report = importer.import_from_dict(data)
        assert report.success is True
        assert report.study_plans_count == 1

    def test_import_all_categories(self, importer: BackupImporter) -> None:
        data = {
            "answer_sheets": [_make_answer_sheet_dict()],
            "score_reports": [_make_score_report_dict()],
            "mistake_entries": [_make_mistake_entry_dict()],
            "study_plans": [_make_study_plan_dict()],
        }
        report = importer.import_from_dict(data)
        assert report.success is True
        assert report.answer_sheets_count == 1
        assert report.score_reports_count == 1
        assert report.mistake_entries_count == 1
        assert report.study_plans_count == 1


class TestValidationRejection:
    """Test that invalid data is rejected with proper error info."""

    def test_invalid_answer_sheet_rejected(self, importer: BackupImporter) -> None:
        bad_sheet = _make_answer_sheet_dict()
        bad_sheet["status"] = "invalid_status"  # Not a valid SheetStatus
        data = {"answer_sheets": [bad_sheet]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert len(report.validation_errors) > 0
        assert report.validation_errors[0].category == "answer_sheets"

    def test_invalid_mistake_entry_rejected(self, importer: BackupImporter) -> None:
        bad_entry = _make_mistake_entry_dict()
        bad_entry["error_count"] = -1  # Must be positive
        data = {"mistake_entries": [bad_entry]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert len(report.validation_errors) > 0
        assert report.validation_errors[0].category == "mistake_entries"

    def test_invalid_study_plan_rejected(self, importer: BackupImporter) -> None:
        bad_plan = _make_study_plan_dict()
        bad_plan["total_days"] = 0  # Must be >= 1
        data = {"study_plans": [bad_plan]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert len(report.validation_errors) > 0

    def test_non_list_category_rejected(self, importer: BackupImporter) -> None:
        data = {"answer_sheets": "not a list"}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert len(report.validation_errors) > 0
        assert "数组" in report.validation_errors[0].reason

    def test_non_dict_item_rejected(self, importer: BackupImporter) -> None:
        data = {"answer_sheets": ["not a dict"]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert len(report.validation_errors) > 0
        assert "JSON 对象" in report.validation_errors[0].reason

    def test_validation_preserves_existing_data(
        self, importer: BackupImporter, engine: Engine
    ) -> None:
        """Ensure that failed validation does not modify existing data."""
        # First, import valid data
        valid_data = {"mistake_entries": [_make_mistake_entry_dict()]}
        report1 = importer.import_from_dict(valid_data)
        assert report1.success is True

        # Now try to import invalid data
        bad_entry = _make_mistake_entry_dict()
        bad_entry["entry_id"] = "mistake-002"
        bad_entry["question_id"] = "q-003"
        bad_entry["error_count"] = -1  # Invalid
        invalid_data = {"mistake_entries": [bad_entry]}
        report2 = importer.import_from_dict(invalid_data)
        assert report2.success is False

        # Verify original data is still there
        from sqlalchemy import text

        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM mistake_entry")
            ).scalar()
            assert count == 1  # Original entry preserved


class TestIDConflictRejection:
    """Test that duplicate IDs within a backup are rejected (Req 9.10)."""

    def test_duplicate_sheet_id_rejected(self, importer: BackupImporter) -> None:
        sheet1 = _make_answer_sheet_dict()
        sheet2 = _make_answer_sheet_dict()  # Same sheet_id
        data = {"answer_sheets": [sheet1, sheet2]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert any("ID 冲突" in e.reason for e in report.validation_errors)

    def test_duplicate_entry_id_rejected(self, importer: BackupImporter) -> None:
        entry1 = _make_mistake_entry_dict()
        entry2 = _make_mistake_entry_dict()  # Same entry_id
        data = {"mistake_entries": [entry1, entry2]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert any("ID 冲突" in e.reason for e in report.validation_errors)

    def test_duplicate_question_id_in_mistakes_rejected(
        self, importer: BackupImporter
    ) -> None:
        entry1 = _make_mistake_entry_dict()
        entry2 = _make_mistake_entry_dict()
        entry2["entry_id"] = "mistake-002"  # Different entry_id
        # But same question_id → conflict
        data = {"mistake_entries": [entry1, entry2]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert any(
            "question_id" in e.field_path for e in report.validation_errors
        )

    def test_duplicate_plan_id_rejected(self, importer: BackupImporter) -> None:
        plan1 = _make_study_plan_dict()
        plan2 = _make_study_plan_dict()  # Same plan_id
        data = {"study_plans": [plan1, plan2]}
        report = importer.import_from_dict(data)
        assert report.success is False
        assert any("ID 冲突" in e.reason for e in report.validation_errors)


class TestAtomicReplacement:
    """Test that import replaces existing data atomically."""

    def test_import_replaces_existing_data(
        self, importer: BackupImporter, engine: Engine
    ) -> None:
        """First import, then re-import with different data."""
        from sqlalchemy import text

        # First import
        data1 = {"mistake_entries": [_make_mistake_entry_dict()]}
        report1 = importer.import_from_dict(data1)
        assert report1.success is True

        # Second import with different entry
        entry2 = _make_mistake_entry_dict()
        entry2["entry_id"] = "mistake-999"
        entry2["question_id"] = "q-999"
        data2 = {"mistake_entries": [entry2]}
        report2 = importer.import_from_dict(data2)
        assert report2.success is True

        # Verify only the new entry exists
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT entry_id FROM mistake_entry")
            ).fetchall()
            assert len(rows) == 1
            assert rows[0][0] == "mistake-999"


class TestFileImport:
    """Test importing from a file path."""

    def test_import_from_file(
        self, importer: BackupImporter, tmp_path: Path
    ) -> None:
        data = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "answer_sheets": [_make_answer_sheet_dict()],
            "score_reports": [],
            "mistake_entries": [],
            "study_plans": [],
        }
        backup_file = tmp_path / "backup.json"
        backup_file.write_text(json.dumps(data), encoding="utf-8")

        report = importer.import_backup(backup_file)
        assert report.success is True
        assert report.answer_sheets_count == 1

    def test_nonexistent_file_returns_error(
        self, importer: BackupImporter, tmp_path: Path
    ) -> None:
        report = importer.import_backup(tmp_path / "nonexistent.json")
        assert report.success is False
        assert "无法读取" in report.error_message

    def test_invalid_json_file_returns_error(
        self, importer: BackupImporter, tmp_path: Path
    ) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json {{{", encoding="utf-8")
        report = importer.import_backup(bad_file)
        assert report.success is False
        assert "JSON 格式无效" in report.error_message


class TestTopLevelValidation:
    """Test top-level structure validation."""

    def test_non_dict_top_level_rejected(self, importer: BackupImporter) -> None:
        # import_from_dict expects a dict
        report = importer.import_from_dict([])  # type: ignore
        assert report.success is False
        assert "字典" in report.error_message

    def test_file_with_array_top_level_rejected(
        self, importer: BackupImporter, tmp_path: Path
    ) -> None:
        bad_file = tmp_path / "array.json"
        bad_file.write_text("[]", encoding="utf-8")
        report = importer.import_backup(bad_file)
        assert report.success is False
        assert "JSON 对象" in report.error_message
