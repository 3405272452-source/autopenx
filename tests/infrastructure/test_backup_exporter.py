"""Tests for the backup exporter module.

Verifies that BackupExporter correctly:
1. Collects all user data from repositories
2. Serializes using model_dump(mode="json") for Round_Trip compatibility
3. Writes a valid JSON backup file with correct structure
4. Includes metadata (schema_version, generated_at, counts)
5. Produces a filename with timestamp
"""

from __future__ import annotations

import json
import tempfile
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import text

from cet4_app.domain.enums import (
    DayStatus,
    SectionName,
    SessionMode,
    SheetStatus,
    TaskKind,
)
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet
from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.domain.models.study_plan import (
    PlanParams,
    StudyDay,
    StudyPlan,
    StudyTask,
)
from cet4_app.infrastructure.persistence.backup.exporter import (
    BACKUP_SCHEMA_VERSION,
    BackupExporter,
    ExportResult,
)
from cet4_app.infrastructure.persistence.db import create_engine, init_schema, transaction
from cet4_app.infrastructure.repositories.answer_sheet_repo import (
    AnswerSheetRepository,
)
from cet4_app.infrastructure.repositories.mistake_repo import MistakeRepo
from cet4_app.infrastructure.repositories.plan_repo import PlanRepo


def _insert_parent_records(engine, paper_id: str = "paper-001", question_ids: list[str] | None = None):
    """Insert the required parent records (paper_set, paper, question) to satisfy FK constraints."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with transaction(engine) as conn:
        # Insert paper_set if not exists
        conn.execute(
            text(
                "INSERT OR IGNORE INTO paper_set (paper_set_id, exam_period, directory_name, scanned_at) "
                "VALUES (:ps_id, :ep, :dn, :sa)"
            ),
            {"ps_id": "ps-test", "ep": "2024-12", "dn": "test_dir", "sa": now_iso},
        )
        # Insert paper if not exists
        conn.execute(
            text(
                "INSERT OR IGNORE INTO paper "
                "(paper_id, paper_set_id, set_index, audio_status, status, updated_at) "
                "VALUES (:pid, :psid, :si, :aus, :st, :ua)"
            ),
            {
                "pid": paper_id,
                "psid": "ps-test",
                "si": 1,
                "aus": "available",
                "st": "ok",
                "ua": now_iso,
            },
        )
        # Insert question records if needed
        if question_ids:
            for qid in question_ids:
                conn.execute(
                    text(
                        "INSERT OR IGNORE INTO question "
                        "(question_id, paper_id, section, question_type, prompt, score) "
                        "VALUES (:qid, :pid, :sec, :qt, :pr, :sc)"
                    ),
                    {
                        "qid": qid,
                        "pid": paper_id,
                        "sec": "reading",
                        "qt": "reading_careful_choice",
                        "pr": "Test question",
                        "sc": 2.0,
                    },
                )


@pytest.fixture()
def tmp_env(tmp_path: Path):
    """Create a temporary database and backup directory for testing."""
    db_path = tmp_path / "test.db"
    backup_dir = tmp_path / "backup"
    engine = create_engine(db_path)
    init_schema(engine)
    return engine, backup_dir


@pytest.fixture()
def now():
    """A fixed UTC timestamp for test data."""
    return datetime(2025, 3, 15, 10, 22, 31, tzinfo=timezone.utc)


class TestBackupExporterEmptyDB:
    """Tests with an empty database — no user data."""

    def test_export_empty_db_produces_valid_json(self, tmp_env):
        engine, backup_dir = tmp_env
        exporter = BackupExporter(engine, backup_dir)

        result = exporter.export()

        assert isinstance(result, ExportResult)
        assert result.file_path.exists()
        assert result.file_path.suffix == ".json"
        assert result.counts == {
            "answer_sheets": 0,
            "score_reports": 0,
            "mistake_entries": 0,
            "study_plans": 0,
            "progress_snapshots": 1,  # Always includes a snapshot
        }

    def test_export_empty_db_file_structure(self, tmp_env):
        engine, backup_dir = tmp_env
        exporter = BackupExporter(engine, backup_dir)

        result = exporter.export()

        with open(result.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["schema_version"] == BACKUP_SCHEMA_VERSION
        assert "generated_at" in data
        assert data["answer_sheets"] == []
        assert data["score_reports"] == []
        assert data["mistake_entries"] == []
        assert data["study_plans"] == []
        assert len(data["progress_snapshots"]) == 1

    def test_export_filename_contains_timestamp(self, tmp_env):
        engine, backup_dir = tmp_env
        exporter = BackupExporter(engine, backup_dir)

        result = exporter.export()

        # Filename should match pattern: backup_YYYYMMDD_HHMMSS.json
        assert result.file_path.name.startswith("backup_")
        assert result.file_path.name.endswith(".json")


class TestBackupExporterWithData:
    """Tests with populated database."""

    def test_export_answer_sheets(self, tmp_env, now):
        engine, backup_dir = tmp_env
        _insert_parent_records(engine, "paper-001", ["q1"])

        sheet = AnswerSheet(
            sheet_id="sheet-001",
            paper_id="paper-001",
            status=SheetStatus.submitted,
            mode=SessionMode.practice,
            started_at=now,
            submitted_at=now,
            updated_at=now,
            elapsed_seconds=3600,
            answers={
                "q1": Answer(
                    question_id="q1", user_answer="A", last_updated_at=now
                ),
            },
        )
        AnswerSheetRepository(engine).save_sheet(sheet)

        exporter = BackupExporter(engine, backup_dir)
        result = exporter.export()

        with open(result.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["answer_sheets"]) == 1
        assert data["answer_sheets"][0]["sheet_id"] == "sheet-001"
        assert data["answer_sheets"][0]["paper_id"] == "paper-001"
        assert result.counts["answer_sheets"] == 1

    def test_export_mistake_entries(self, tmp_env, now):
        engine, backup_dir = tmp_env
        _insert_parent_records(engine, "paper-001", ["q1"])

        entry = MistakeEntry(
            entry_id="me-001",
            question_id="q1",
            paper_id="paper-001",
            first_wrong_at=now,
            last_wrong_at=now,
            error_count=1,
            redo_count=0,
            correct_streak=0,
            mastered=False,
            notes="test note",
            tags=["vocabulary"],
        )
        MistakeRepo(engine).save_entry(entry)

        exporter = BackupExporter(engine, backup_dir)
        result = exporter.export()

        with open(result.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["mistake_entries"]) == 1
        assert data["mistake_entries"][0]["entry_id"] == "me-001"
        assert data["mistake_entries"][0]["notes"] == "test note"
        assert result.counts["mistake_entries"] == 1

    def test_export_study_plans(self, tmp_env, now):
        engine, backup_dir = tmp_env

        start = date(2025, 3, 15)
        plan = StudyPlan(
            plan_id="plan-001",
            start_date=start,
            total_days=1,
            params=PlanParams(
                start_date=start,
                daily_minutes_cap=120,
                section_ratio={
                    SectionName.writing: 25,
                    SectionName.listening: 25,
                    SectionName.reading: 25,
                    SectionName.translation: 25,
                },
            ),
            days=[
                StudyDay(
                    day_index=1,
                    date=start,
                    tasks=[
                        StudyTask(
                            task_id="task-001",
                            kind=TaskKind.paper,
                            paper_id="paper-001",
                        ),
                    ],
                    status=DayStatus.pending,
                ),
            ],
        )
        PlanRepo(engine).save_plan(plan)

        exporter = BackupExporter(engine, backup_dir)
        result = exporter.export()

        with open(result.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["study_plans"]) == 1
        assert data["study_plans"][0]["plan_id"] == "plan-001"
        assert result.counts["study_plans"] == 1

    def test_export_round_trip_answer_sheet(self, tmp_env, now):
        """Verify that exported AnswerSheet data can be deserialized back."""
        engine, backup_dir = tmp_env
        _insert_parent_records(engine, "paper-rt", ["q1", "q2"])

        sheet = AnswerSheet(
            sheet_id="sheet-rt",
            paper_id="paper-rt",
            status=SheetStatus.submitted,
            mode=SessionMode.practice,
            started_at=now,
            submitted_at=now,
            updated_at=now,
            elapsed_seconds=1800,
            answers={
                "q1": Answer(
                    question_id="q1", user_answer="B", last_updated_at=now
                ),
                "q2": Answer(
                    question_id="q2", user_answer="hello world", last_updated_at=now
                ),
            },
        )
        AnswerSheetRepository(engine).save_sheet(sheet)

        exporter = BackupExporter(engine, backup_dir)
        result = exporter.export()

        with open(result.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Round-trip: deserialize back to domain model
        restored = AnswerSheet.model_validate(data["answer_sheets"][0])
        assert restored.sheet_id == sheet.sheet_id
        assert restored.paper_id == sheet.paper_id
        assert restored.status == sheet.status
        assert restored.elapsed_seconds == sheet.elapsed_seconds
        assert len(restored.answers) == 2

    def test_export_round_trip_mistake_entry(self, tmp_env, now):
        """Verify that exported MistakeEntry data can be deserialized back."""
        engine, backup_dir = tmp_env
        _insert_parent_records(engine, "paper-rt", ["q-rt"])

        entry = MistakeEntry(
            entry_id="me-rt",
            question_id="q-rt",
            paper_id="paper-rt",
            first_wrong_at=now,
            last_wrong_at=now,
            error_count=3,
            redo_count=1,
            correct_streak=0,
            mastered=False,
            notes="round trip test",
            tags=["grammar", "hard"],
        )
        MistakeRepo(engine).save_entry(entry)

        exporter = BackupExporter(engine, backup_dir)
        result = exporter.export()

        with open(result.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        restored = MistakeEntry.model_validate(data["mistake_entries"][0])
        assert restored.entry_id == entry.entry_id
        assert restored.error_count == entry.error_count
        assert restored.notes == entry.notes
        assert restored.tags == entry.tags

    def test_export_progress_snapshot_content(self, tmp_env, now):
        """Verify progress snapshot contains expected summary data."""
        engine, backup_dir = tmp_env
        _insert_parent_records(engine, "paper-prog", ["q-prog"])

        # Add a submitted sheet
        sheet = AnswerSheet(
            sheet_id="sheet-prog",
            paper_id="paper-prog",
            status=SheetStatus.submitted,
            mode=SessionMode.practice,
            started_at=now,
            submitted_at=now,
            updated_at=now,
            elapsed_seconds=2400,
        )
        AnswerSheetRepository(engine).save_sheet(sheet)

        # Add a mistake entry
        entry = MistakeEntry(
            entry_id="me-prog",
            question_id="q-prog",
            paper_id="paper-prog",
            first_wrong_at=now,
            last_wrong_at=now,
            error_count=1,
        )
        MistakeRepo(engine).save_entry(entry)

        exporter = BackupExporter(engine, backup_dir)
        result = exporter.export()

        with open(result.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        snapshot = data["progress_snapshots"][0]
        assert snapshot["submitted_papers"] == 1
        assert "snapshot_at" in snapshot
        assert snapshot["mistake_book_summary"]["total_entries"] == 1
        assert snapshot["mistake_book_summary"]["mastered_count"] == 0
        assert snapshot["mistake_book_summary"]["active_count"] == 1

    def test_export_creates_output_directory(self, tmp_path, now):
        """Verify that the exporter creates the output directory if missing."""
        db_path = tmp_path / "test.db"
        backup_dir = tmp_path / "nested" / "backup" / "dir"
        engine = create_engine(db_path)
        init_schema(engine)

        exporter = BackupExporter(engine, backup_dir)
        result = exporter.export()

        assert backup_dir.exists()
        assert result.file_path.exists()
