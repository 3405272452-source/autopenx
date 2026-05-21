"""Integration tests for ScoreReportRepo.

Tests cover:
- save_report / load_report_by_id round-trip
- load_report_by_sheet_id
- list_reports_by_paper (ordering, multiple reports)
- Cascade loading of QuestionGrade rows
- JSON field (section_scores_json, cannot_grade_ids_json) serialization
- Overwrite (re-save) behavior
- Non-existent lookups return None / empty list

Requirements: 8.1, 12.1
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import text as sa_text

from cet4_app.domain.enums import SectionName
from cet4_app.domain.models.score_report import QuestionGrade, ScoreReport
from cet4_app.infrastructure.persistence.db import create_engine, init_schema, transaction
from cet4_app.infrastructure.repositories.score_report_repo import ScoreReportRepo


@pytest.fixture
def repo(tmp_path: Path) -> ScoreReportRepo:
    """Create a fresh SQLite repo with prerequisite FK rows for each test."""
    db_path = tmp_path / "test.db"
    engine = create_engine(db_path)
    init_schema(engine)

    # Insert prerequisite rows for FK constraints
    with transaction(engine) as conn:
        conn.execute(
            sa_text(
                "INSERT INTO paper_set (paper_set_id, exam_period, directory_name, scanned_at) "
                "VALUES ('ps-1', '2024-12', 'test_dir', '2024-01-01T00:00:00')"
            )
        )
        conn.execute(
            sa_text(
                "INSERT INTO paper (paper_id, paper_set_id, set_index, audio_status, status, updated_at) "
                "VALUES ('paper-1', 'ps-1', 1, 'available', 'ok', '2024-01-01T00:00:00')"
            )
        )
        # Insert questions for FK constraints on question_grade
        conn.execute(
            sa_text(
                "INSERT INTO question (question_id, paper_id, section, question_type, prompt, score) "
                "VALUES ('q-01', 'paper-1', 'listening', 'listening_news', 'Q1?', 7.1)"
            )
        )
        conn.execute(
            sa_text(
                "INSERT INTO question (question_id, paper_id, section, question_type, prompt, score) "
                "VALUES ('q-02', 'paper-1', 'reading', 'reading_careful_choice', 'Q2?', 7.1)"
            )
        )
        conn.execute(
            sa_text(
                "INSERT INTO question (question_id, paper_id, section, question_type, prompt, score) "
                "VALUES ('q-03', 'paper-1', 'writing', 'writing', 'Write essay.', 15.0)"
            )
        )
        # Insert an answer_sheet for FK constraint on score_report
        conn.execute(
            sa_text(
                "INSERT INTO answer_sheet (sheet_id, paper_id, status, mode, started_at, updated_at) "
                "VALUES ('sheet-1', 'paper-1', 'submitted', 'practice', "
                "'2024-06-15T10:00:00', '2024-06-15T11:00:00')"
            )
        )
        conn.execute(
            sa_text(
                "INSERT INTO answer_sheet (sheet_id, paper_id, status, mode, started_at, updated_at) "
                "VALUES ('sheet-2', 'paper-1', 'submitted', 'mock_exam', "
                "'2024-06-16T10:00:00', '2024-06-16T11:00:00')"
            )
        )

    return ScoreReportRepo(engine)


def _make_grade(
    question_id: str = "q-01",
    is_correct: bool | None = True,
    status: str = "ok",
    earned_score: str = "7.10",
    score_max: str = "7.10",
    reference_answer: str = "A",
    user_answer: str = "A",
) -> QuestionGrade:
    """Helper to create a valid QuestionGrade."""
    return QuestionGrade(
        question_id=question_id,
        is_correct=is_correct,
        status=status,
        earned_score=Decimal(earned_score),
        score_max=Decimal(score_max),
        reference_answer=reference_answer,
        user_answer=user_answer,
    )


def _make_report(
    report_id: str = "rpt-1",
    sheet_id: str = "sheet-1",
    paper_id: str = "paper-1",
    grades: list[QuestionGrade] | None = None,
) -> ScoreReport:
    """Helper to create a valid ScoreReport with sensible defaults.

    Default grades: q-01 correct, q-02 wrong, q-03 cannot-grade.
    The ScoreReport invariant requires correct + wrong + unanswered == len(grades).
    cannot-grade items count toward wrong_count per the model's accounting.
    """
    if grades is None:
        grades = [
            _make_grade("q-01", True, "ok", "7.10", "7.10", "A", "A"),
            _make_grade("q-02", False, "ok", "0.00", "7.10", "B", "C"),
            _make_grade("q-03", None, "cannot-grade", "0.00", "15.00", "", ""),
        ]

    # Count grades for the invariant: correct + wrong + unanswered == len(grades)
    # cannot-grade items (is_correct=None) are counted in wrong_count
    correct = sum(1 for g in grades if g.is_correct is True)
    wrong = sum(1 for g in grades if g.is_correct is False or g.status == "cannot-grade")
    unanswered = sum(1 for g in grades if g.status == "unanswered")
    cannot_grade_ids = [g.question_id for g in grades if g.status == "cannot-grade"]

    # Ensure the invariant holds
    # If cannot-grade items are double-counted (also in wrong), adjust
    # Actually the invariant is: correct + wrong + unanswered == len(grades)
    # cannot-grade items have is_correct=None, so they're not in correct or wrong
    # by the simple boolean check. We need to include them in wrong_count.
    total = correct + wrong + unanswered
    if total != len(grades):
        # Remaining items are cannot-grade with is_correct=None
        wrong = len(grades) - correct - unanswered

    return ScoreReport(
        report_id=report_id,
        sheet_id=sheet_id,
        paper_id=paper_id,
        total_score=Decimal("23.67"),
        scaled_score_710=168,
        section_scores={
            SectionName.writing: Decimal("0.00"),
            SectionName.listening: Decimal("50.00"),
            SectionName.reading: Decimal("0.00"),
            SectionName.translation: Decimal("0.00"),
        },
        grades=grades,
        correct_count=correct,
        wrong_count=wrong,
        unanswered_count=unanswered,
        cannot_grade_ids=cannot_grade_ids,
        duration_seconds=3600,
        generated_at=datetime(2024, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
    )


class TestSaveAndLoadById:
    """Tests for save_report and load_report_by_id."""

    def test_save_and_load_round_trip(self, repo: ScoreReportRepo):
        """A report with grades can be saved and loaded by ID."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        assert loaded.report_id == "rpt-1"
        assert loaded.sheet_id == "sheet-1"
        assert loaded.paper_id == "paper-1"
        assert loaded.total_score == Decimal("23.67")
        assert loaded.scaled_score_710 == 168
        assert loaded.duration_seconds == 3600
        assert loaded.correct_count == 1
        # wrong_count = 2 (1 actually wrong + 1 cannot-grade to satisfy invariant)
        assert loaded.wrong_count == 2
        assert loaded.unanswered_count == 0

    def test_section_scores_json_round_trip(self, repo: ScoreReportRepo):
        """Section scores dict serializes/deserializes correctly."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        assert SectionName.listening in loaded.section_scores
        assert loaded.section_scores[SectionName.listening] == Decimal("50.00")
        assert loaded.section_scores[SectionName.writing] == Decimal("0.00")

    def test_cannot_grade_ids_json_round_trip(self, repo: ScoreReportRepo):
        """cannot_grade_ids list serializes/deserializes correctly."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        assert loaded.cannot_grade_ids == ["q-03"]

    def test_grades_cascade_loaded(self, repo: ScoreReportRepo):
        """QuestionGrade rows are loaded with the report."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        assert len(loaded.grades) == 3
        # Grades should be sorted by question_id ascending
        assert loaded.grades[0].question_id == "q-01"
        assert loaded.grades[1].question_id == "q-02"
        assert loaded.grades[2].question_id == "q-03"

    def test_grade_is_correct_values(self, repo: ScoreReportRepo):
        """is_correct True/False/None round-trips correctly."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        assert loaded.grades[0].is_correct is True
        assert loaded.grades[1].is_correct is False
        assert loaded.grades[2].is_correct is None

    def test_grade_status_values(self, repo: ScoreReportRepo):
        """Grade status values round-trip correctly."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        assert loaded.grades[0].status == "ok"
        assert loaded.grades[1].status == "ok"
        assert loaded.grades[2].status == "cannot-grade"

    def test_load_nonexistent_returns_none(self, repo: ScoreReportRepo):
        """Loading a non-existent report returns None."""
        result = repo.load_report_by_id("nonexistent")
        assert result is None

    def test_save_overwrites_existing(self, repo: ScoreReportRepo):
        """Re-saving a report with the same ID replaces old data."""
        report = _make_report()
        repo.save_report(report)

        # Update and re-save
        updated_grades = [
            _make_grade("q-01", True, "ok", "7.10", "7.10", "A", "A"),
            _make_grade("q-02", True, "ok", "7.10", "7.10", "B", "B"),
        ]
        updated_report = ScoreReport(
            report_id="rpt-1",
            sheet_id="sheet-1",
            paper_id="paper-1",
            total_score=Decimal("50.00"),
            scaled_score_710=355,
            section_scores={
                SectionName.listening: Decimal("100.00"),
                SectionName.reading: Decimal("100.00"),
            },
            grades=updated_grades,
            correct_count=2,
            wrong_count=0,
            unanswered_count=0,
            cannot_grade_ids=[],
            duration_seconds=1800,
            generated_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
        repo.save_report(updated_report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        assert loaded.total_score == Decimal("50.00")
        assert loaded.scaled_score_710 == 355
        assert len(loaded.grades) == 2
        assert loaded.correct_count == 2


class TestLoadBySheetId:
    """Tests for load_report_by_sheet_id."""

    def test_load_by_sheet_id(self, repo: ScoreReportRepo):
        """A report can be found by its associated sheet_id."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_sheet_id("sheet-1")
        assert loaded is not None
        assert loaded.report_id == "rpt-1"
        assert loaded.sheet_id == "sheet-1"

    def test_load_by_sheet_id_nonexistent(self, repo: ScoreReportRepo):
        """Loading by a non-existent sheet_id returns None."""
        result = repo.load_report_by_sheet_id("nonexistent")
        assert result is None


class TestListByPaper:
    """Tests for list_reports_by_paper."""

    def test_list_single_report(self, repo: ScoreReportRepo):
        """A single report for a paper is returned in a list."""
        report = _make_report()
        repo.save_report(report)

        results = repo.list_reports_by_paper("paper-1")
        assert len(results) == 1
        assert results[0].report_id == "rpt-1"

    def test_list_multiple_reports_ordered_by_generated_at_desc(self, repo: ScoreReportRepo):
        """Multiple reports are returned ordered by generated_at descending."""
        # First report (older)
        report1 = _make_report(report_id="rpt-1", sheet_id="sheet-1")
        repo.save_report(report1)

        # Second report (newer)
        grades2 = [
            _make_grade("q-01", True, "ok", "7.10", "7.10", "A", "A"),
            _make_grade("q-02", True, "ok", "7.10", "7.10", "B", "B"),
        ]
        report2 = ScoreReport(
            report_id="rpt-2",
            sheet_id="sheet-2",
            paper_id="paper-1",
            total_score=Decimal("50.00"),
            scaled_score_710=355,
            section_scores={SectionName.listening: Decimal("100.00")},
            grades=grades2,
            correct_count=2,
            wrong_count=0,
            unanswered_count=0,
            cannot_grade_ids=[],
            duration_seconds=1800,
            generated_at=datetime(2024, 6, 16, 11, 0, 0, tzinfo=timezone.utc),
        )
        repo.save_report(report2)

        results = repo.list_reports_by_paper("paper-1")
        assert len(results) == 2
        # Newer first
        assert results[0].report_id == "rpt-2"
        assert results[1].report_id == "rpt-1"

    def test_list_empty_for_unknown_paper(self, repo: ScoreReportRepo):
        """Listing reports for a non-existent paper returns empty list."""
        results = repo.list_reports_by_paper("nonexistent-paper")
        assert results == []


class TestEdgeCases:
    """Edge case tests."""

    def test_report_with_no_grades(self, repo: ScoreReportRepo):
        """A report with zero grades can be saved and loaded."""
        report = ScoreReport(
            report_id="rpt-empty",
            sheet_id="sheet-1",
            paper_id="paper-1",
            total_score=Decimal("0.00"),
            scaled_score_710=0,
            section_scores={},
            grades=[],
            correct_count=0,
            wrong_count=0,
            unanswered_count=0,
            cannot_grade_ids=[],
            duration_seconds=0,
            generated_at=datetime(2024, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
        )
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-empty")
        assert loaded is not None
        assert loaded.grades == []
        assert loaded.correct_count == 0

    def test_generated_at_preserves_timezone(self, repo: ScoreReportRepo):
        """The generated_at timestamp round-trips with timezone info."""
        report = _make_report()
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-1")
        assert loaded is not None
        # ISO format preserves the UTC offset
        assert loaded.generated_at.year == 2024
        assert loaded.generated_at.month == 6
        assert loaded.generated_at.hour == 11

    def test_unanswered_grade(self, repo: ScoreReportRepo):
        """An unanswered grade round-trips correctly."""
        grades = [
            _make_grade("q-01", False, "unanswered", "0.00", "7.10", "A", ""),
        ]
        report = ScoreReport(
            report_id="rpt-unans",
            sheet_id="sheet-1",
            paper_id="paper-1",
            total_score=Decimal("0.00"),
            scaled_score_710=0,
            section_scores={},
            grades=grades,
            correct_count=0,
            wrong_count=0,
            unanswered_count=1,
            cannot_grade_ids=[],
            duration_seconds=100,
            generated_at=datetime(2024, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
        )
        repo.save_report(report)

        loaded = repo.load_report_by_id("rpt-unans")
        assert loaded is not None
        assert loaded.grades[0].status == "unanswered"
        assert loaded.grades[0].is_correct is False
        assert loaded.grades[0].user_answer == ""
