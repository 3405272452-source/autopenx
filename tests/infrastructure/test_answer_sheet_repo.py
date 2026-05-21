"""Integration tests for AnswerSheetRepository.

Tests cover:
- save_sheet / load_sheet_by_id round-trip
- Cascade loading of Answer rows
- update_sheet_status transitions
- save_draft / load_latest_draft for 30-second auto-save
- Composite primary key (sheet_id, question_id) handling
- JSON field (rubric_json) serialization/deserialization

Requirements: 4.5, 4.7, 12.1, 12.2
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cet4_app.domain.enums import SessionMode, SheetStatus
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet, RubricScore
from cet4_app.infrastructure.persistence.db import create_engine, init_schema
from cet4_app.infrastructure.repositories.answer_sheet_repo import AnswerSheetRepository


@pytest.fixture
def repo(tmp_path: Path) -> AnswerSheetRepository:
    """Create a fresh in-memory-like SQLite repo for each test."""
    db_path = tmp_path / "test.db"
    engine = create_engine(db_path)
    init_schema(engine)

    # We need to insert a paper_set and paper first due to FK constraints
    from cet4_app.infrastructure.persistence.db import transaction

    with transaction(engine) as conn:
        from sqlalchemy import text

        conn.execute(
            text(
                """
                INSERT INTO paper_set (paper_set_id, exam_period, directory_name, scanned_at)
                VALUES ('ps-1', '2024-12', 'test_dir', '2024-01-01T00:00:00')
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO paper (paper_id, paper_set_id, set_index, audio_status, status, updated_at)
                VALUES ('paper-1', 'ps-1', 1, 'available', 'ok', '2024-01-01T00:00:00')
                """
            )
        )
        # Insert a question for FK constraint on answer table
        conn.execute(
            text(
                """
                INSERT INTO question (question_id, paper_id, section, question_type, prompt, score)
                VALUES ('q-1', 'paper-1', 'listening', 'listening_news', 'What happened?', 7.1)
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO question (question_id, paper_id, section, question_type, prompt, score)
                VALUES ('q-2', 'paper-1', 'reading', 'reading_careful_choice', 'What is the main idea?', 7.1)
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO question (question_id, paper_id, section, question_type, prompt, score)
                VALUES ('q-3', 'paper-1', 'writing', 'writing', 'Write an essay.', 15.0)
                """
            )
        )

    return AnswerSheetRepository(engine)


def _make_sheet(
    sheet_id: str = "sheet-1",
    paper_id: str = "paper-1",
    status: SheetStatus = SheetStatus.in_progress,
    mode: SessionMode = SessionMode.practice,
    answers: dict[str, Answer] | None = None,
    mock_deadline: datetime | None = None,
) -> AnswerSheet:
    """Helper to create a valid AnswerSheet for testing."""
    now = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
    return AnswerSheet(
        sheet_id=sheet_id,
        paper_id=paper_id,
        status=status,
        mode=mode,
        started_at=now,
        updated_at=now,
        elapsed_seconds=120,
        answers=answers or {},
        mock_deadline=mock_deadline,
    )


def _make_answer(
    question_id: str = "q-1",
    user_answer: str = "A",
    rubric: RubricScore | None = None,
) -> Answer:
    """Helper to create a valid Answer for testing."""
    return Answer(
        question_id=question_id,
        user_answer=user_answer,
        last_updated_at=datetime(2024, 6, 15, 10, 5, 0, tzinfo=timezone.utc),
        rubric=rubric,
    )


class TestSaveAndLoadSheet:
    """Tests for save_sheet and load_sheet_by_id."""

    def test_save_and_load_empty_sheet(self, repo: AnswerSheetRepository):
        """A sheet with no answers can be saved and loaded."""
        sheet = _make_sheet()
        repo.save_sheet(sheet)

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        assert loaded.sheet_id == "sheet-1"
        assert loaded.paper_id == "paper-1"
        assert loaded.status == SheetStatus.in_progress
        assert loaded.mode == SessionMode.practice
        assert loaded.elapsed_seconds == 120
        assert loaded.answers == {}

    def test_save_and_load_with_answers(self, repo: AnswerSheetRepository):
        """A sheet with multiple answers round-trips correctly."""
        answers = {
            "q-1": _make_answer("q-1", "B"),
            "q-2": _make_answer("q-2", "C"),
        }
        sheet = _make_sheet(answers=answers)
        repo.save_sheet(sheet)

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        assert len(loaded.answers) == 2
        assert loaded.answers["q-1"].user_answer == "B"
        assert loaded.answers["q-2"].user_answer == "C"

    def test_save_with_rubric_json(self, repo: AnswerSheetRepository):
        """RubricScore is correctly serialized/deserialized via JSON."""
        rubric = RubricScore(content=4, structure=3, language=5, word_count=2)
        answers = {"q-3": _make_answer("q-3", "My essay text...", rubric=rubric)}
        sheet = _make_sheet(answers=answers)
        repo.save_sheet(sheet)

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        loaded_answer = loaded.answers["q-3"]
        assert loaded_answer.rubric is not None
        assert loaded_answer.rubric.content == 4
        assert loaded_answer.rubric.structure == 3
        assert loaded_answer.rubric.language == 5
        assert loaded_answer.rubric.word_count == 2

    def test_save_overwrites_existing(self, repo: AnswerSheetRepository):
        """Saving a sheet again replaces the old data."""
        sheet = _make_sheet(answers={"q-1": _make_answer("q-1", "A")})
        repo.save_sheet(sheet)

        # Update the answer
        sheet2 = _make_sheet(answers={"q-1": _make_answer("q-1", "D")})
        repo.save_sheet(sheet2)

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        assert loaded.answers["q-1"].user_answer == "D"

    def test_load_nonexistent_returns_none(self, repo: AnswerSheetRepository):
        """Loading a non-existent sheet returns None."""
        result = repo.load_sheet_by_id("nonexistent")
        assert result is None

    def test_save_mock_exam_with_deadline(self, repo: AnswerSheetRepository):
        """Mock exam sheets with deadline round-trip correctly."""
        deadline = datetime(2024, 6, 15, 12, 5, 0, tzinfo=timezone.utc)
        sheet = _make_sheet(
            mode=SessionMode.mock_exam,
            mock_deadline=deadline,
        )
        repo.save_sheet(sheet)

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        assert loaded.mode == SessionMode.mock_exam
        assert loaded.mock_deadline is not None
        assert loaded.mock_deadline.year == 2024
        assert loaded.mock_deadline.hour == 12
        assert loaded.mock_deadline.minute == 5


class TestUpdateSheetStatus:
    """Tests for update_sheet_status."""

    def test_update_to_submitted(self, repo: AnswerSheetRepository):
        """Status can be transitioned to submitted with a timestamp."""
        sheet = _make_sheet()
        repo.save_sheet(sheet)

        submit_time = datetime(2024, 6, 15, 11, 0, 0, tzinfo=timezone.utc)
        result = repo.update_sheet_status(
            "sheet-1",
            SheetStatus.submitted,
            submitted_at=submit_time,
            elapsed_seconds=3600,
        )
        assert result is True

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        assert loaded.status == SheetStatus.submitted
        assert loaded.submitted_at is not None
        assert loaded.elapsed_seconds == 3600

    def test_update_to_paused(self, repo: AnswerSheetRepository):
        """Status can be transitioned to paused."""
        sheet = _make_sheet()
        repo.save_sheet(sheet)

        result = repo.update_sheet_status(
            "sheet-1", SheetStatus.paused, elapsed_seconds=500
        )
        assert result is True

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        assert loaded.status == SheetStatus.paused
        assert loaded.elapsed_seconds == 500

    def test_update_nonexistent_returns_false(self, repo: AnswerSheetRepository):
        """Updating a non-existent sheet returns False."""
        result = repo.update_sheet_status("nonexistent", SheetStatus.paused)
        assert result is False


class TestDraft:
    """Tests for save_draft and load_latest_draft."""

    def test_save_draft_updates_timestamp(self, repo: AnswerSheetRepository):
        """save_draft updates draft_saved_at and persists answers."""
        sheet = _make_sheet(answers={"q-1": _make_answer("q-1", "A")})
        repo.save_sheet(sheet)

        # Add a new answer and save as draft
        sheet_updated = _make_sheet(
            answers={
                "q-1": _make_answer("q-1", "B"),
                "q-2": _make_answer("q-2", "C"),
            }
        )
        repo.save_draft(sheet_updated)

        loaded = repo.load_sheet_by_id("sheet-1")
        assert loaded is not None
        assert loaded.draft_saved_at is not None
        assert len(loaded.answers) == 2
        assert loaded.answers["q-1"].user_answer == "B"
        assert loaded.answers["q-2"].user_answer == "C"

    def test_load_latest_draft_finds_most_recent(self, repo: AnswerSheetRepository):
        """load_latest_draft returns the most recently saved draft."""
        sheet = _make_sheet()
        repo.save_sheet(sheet)
        repo.save_draft(sheet)

        loaded = repo.load_latest_draft("paper-1")
        assert loaded is not None
        assert loaded.sheet_id == "sheet-1"

    def test_load_latest_draft_ignores_submitted(self, repo: AnswerSheetRepository):
        """load_latest_draft does not return submitted sheets."""
        sheet = _make_sheet()
        repo.save_sheet(sheet)

        # Submit the sheet
        submit_time = datetime(2024, 6, 15, 11, 0, 0, tzinfo=timezone.utc)
        repo.update_sheet_status(
            "sheet-1", SheetStatus.submitted, submitted_at=submit_time
        )

        loaded = repo.load_latest_draft("paper-1")
        assert loaded is None

    def test_load_latest_draft_no_drafts(self, repo: AnswerSheetRepository):
        """load_latest_draft returns None when no drafts exist."""
        loaded = repo.load_latest_draft("paper-1")
        assert loaded is None

    def test_load_latest_draft_picks_most_recent(self, repo: AnswerSheetRepository):
        """When multiple drafts exist, the most recent is returned."""
        # First sheet - older
        sheet1 = _make_sheet(sheet_id="sheet-1")
        repo.save_sheet(sheet1)
        repo.save_draft(sheet1)

        # Second sheet - newer (will have a later draft_saved_at)
        sheet2 = _make_sheet(sheet_id="sheet-2")
        repo.save_sheet(sheet2)
        repo.save_draft(sheet2)

        loaded = repo.load_latest_draft("paper-1")
        assert loaded is not None
        # The second sheet should be returned as it was drafted more recently
        assert loaded.sheet_id == "sheet-2"
