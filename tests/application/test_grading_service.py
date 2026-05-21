"""Unit tests for application/grading_service.py.

Tests the GradingService orchestration:
- Objective auto-grading is invoked and results are included in the report.
- Subjective questions with rubrics are graded; without rubrics get pending status.
- ScoreReport is persisted to the repository.
- Mistake book is updated with wrong answers (Req 9.1, 9.2).
- Manual rubric submission triggers recalculation (Req 7.6).

Requirements covered: 6.1, 6.4, 7.6, 8.1, 9.1, 9.2.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

import pytest

from cet4_app.application.grading_service import GradingService
from cet4_app.domain.enums import (
    PaperStatus,
    QuestionType,
    SectionName,
    SessionMode,
    SheetStatus,
)
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet, RubricScore
from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.domain.models.question import Paper, Question, Section, SubSection
from cet4_app.domain.models.score_report import QuestionGrade, ScoreReport


# ---------------------------------------------------------------------------
# In-memory fake repositories
# ---------------------------------------------------------------------------


class FakeScoreReportRepo:
    """In-memory fake for ScoreReportRepository protocol."""

    def __init__(self) -> None:
        self.reports: list[ScoreReport] = []

    def save_report(self, report: ScoreReport) -> None:
        self.reports.append(report)


class FakeMistakeRepo:
    """In-memory fake for MistakeRepository protocol."""

    def __init__(self) -> None:
        self.entries: dict[str, MistakeEntry] = {}

    def save_entry(self, entry: MistakeEntry) -> None:
        self.entries[entry.question_id] = entry

    def update_entry(self, entry: MistakeEntry) -> None:
        self.entries[entry.question_id] = entry

    def load_by_question_id(self, question_id: str) -> Optional[MistakeEntry]:
        return self.entries.get(question_id)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


def _make_paper_with_questions() -> Paper:
    """Create a minimal Paper with both objective and subjective questions."""
    listening_q = Question(
        id="2024-12-set1-listening-news-01",
        paper_id="paper-001",
        section=SectionName.listening,
        sub_section="news",
        question_type=QuestionType.listening_news,
        prompt="What is the news about?",
        options=["Option A", "Option B", "Option C", "Option D"],
        correct_letter="A",
        reference_answer="",
        explanation="The answer is A because...",
        score=Decimal("7.10"),
        tags=[],
    )

    reading_q = Question(
        id="2024-12-set1-reading-careful-01",
        paper_id="paper-001",
        section=SectionName.reading,
        sub_section="careful",
        question_type=QuestionType.reading_careful_choice,
        prompt="What does the author imply?",
        options=["Choice A", "Choice B", "Choice C", "Choice D"],
        correct_letter="B",
        reference_answer="",
        explanation="B is correct because...",
        score=Decimal("14.20"),
        tags=[],
    )

    writing_q = Question(
        id="2024-12-set1-writing-01",
        paper_id="paper-001",
        section=SectionName.writing,
        sub_section="",
        question_type=QuestionType.writing,
        prompt="Write an essay on the topic...",
        options=[],
        reference_answer="Sample essay text here.",
        explanation="Key points: structure, grammar, content.",
        score=Decimal("15.00"),
        tags=[],
        min_words=120,
    )

    listening_section = Section(
        name=SectionName.listening,
        sub_sections=[
            SubSection(name="news", questions=[listening_q])
        ],
        status="ok",
    )
    reading_section = Section(
        name=SectionName.reading,
        sub_sections=[
            SubSection(name="careful", questions=[reading_q])
        ],
        status="ok",
    )
    writing_section = Section(
        name=SectionName.writing,
        sub_sections=[
            SubSection(name="writing", questions=[writing_q])
        ],
        status="ok",
    )

    return Paper(
        paper_id="paper-001",
        paper_set_id="ps-001",
        exam_period="2024-12",
        set_index=1,
        audio_status="available",
        status="ok",
        sections=[writing_section, listening_section, reading_section],
        shared_banked_words=[],
        long_reading_paragraphs={},
    )


def _make_answer_sheet(
    *,
    listening_answer: str = "A",
    reading_answer: str = "C",  # Wrong answer (correct is B)
    writing_rubric: Optional[RubricScore] = None,
) -> AnswerSheet:
    """Create a submitted AnswerSheet with given answers."""
    now = datetime.now(timezone.utc)
    answers: dict[str, Answer] = {
        "2024-12-set1-listening-news-01": Answer(
            question_id="2024-12-set1-listening-news-01",
            user_answer=listening_answer,
            last_updated_at=now,
        ),
        "2024-12-set1-reading-careful-01": Answer(
            question_id="2024-12-set1-reading-careful-01",
            user_answer=reading_answer,
            last_updated_at=now,
        ),
        "2024-12-set1-writing-01": Answer(
            question_id="2024-12-set1-writing-01",
            user_answer="This is my essay about the topic...",
            last_updated_at=now,
            rubric=writing_rubric,
        ),
    }

    return AnswerSheet(
        sheet_id="sheet-001",
        paper_id="paper-001",
        status=SheetStatus.submitted,
        mode=SessionMode.practice,
        started_at=now,
        submitted_at=now,
        updated_at=now,
        elapsed_seconds=3600,
        answers=answers,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGradeAndReport:
    """Tests for GradingService.grade_and_report."""

    def test_produces_score_report(self) -> None:
        """grade_and_report returns a valid ScoreReport."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet()

        report = service.grade_and_report(sheet, paper)

        assert isinstance(report, ScoreReport)
        assert report.sheet_id == "sheet-001"
        assert report.paper_id == "paper-001"

    def test_persists_report_to_repo(self) -> None:
        """grade_and_report saves the report to the repository."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet()

        report = service.grade_and_report(sheet, paper)

        assert len(repo.reports) == 1
        assert repo.reports[0].report_id == report.report_id

    def test_objective_grading_correct_answer(self) -> None:
        """Correct objective answers get is_correct=True."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        # Listening answer "A" is correct
        sheet = _make_answer_sheet(listening_answer="A", reading_answer="B")

        report = service.grade_and_report(sheet, paper)

        # Find the listening grade
        listening_grade = next(
            g for g in report.grades
            if g.question_id == "2024-12-set1-listening-news-01"
        )
        assert listening_grade.is_correct is True
        assert listening_grade.earned_score == Decimal("7.10")

    def test_objective_grading_wrong_answer(self) -> None:
        """Wrong objective answers get is_correct=False."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        # Reading answer "C" is wrong (correct is "B")
        sheet = _make_answer_sheet(reading_answer="C")

        report = service.grade_and_report(sheet, paper)

        reading_grade = next(
            g for g in report.grades
            if g.question_id == "2024-12-set1-reading-careful-01"
        )
        assert reading_grade.is_correct is False
        assert reading_grade.earned_score == Decimal("0.00")

    def test_subjective_without_rubric_is_pending(self) -> None:
        """Subjective questions without rubric get pending-manual-grade status."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet(writing_rubric=None)

        report = service.grade_and_report(sheet, paper)

        writing_grade = next(
            g for g in report.grades
            if g.question_id == "2024-12-set1-writing-01"
        )
        assert writing_grade.status == "pending-manual-grade"
        assert writing_grade.earned_score == Decimal("0.00")

    def test_subjective_with_rubric_is_graded(self) -> None:
        """Subjective questions with rubric get computed earned_score."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        rubric = RubricScore(content=4, structure=4, language=3, word_count=4)
        sheet = _make_answer_sheet(writing_rubric=rubric)

        report = service.grade_and_report(sheet, paper)

        writing_grade = next(
            g for g in report.grades
            if g.question_id == "2024-12-set1-writing-01"
        )
        assert writing_grade.status == "ok"
        # total = 4+4+3+4 = 15; earned = 15/20 * 15.00 = 11.25
        assert writing_grade.earned_score == Decimal("11.25")

    def test_wrong_answers_added_to_mistake_book(self) -> None:
        """Wrong objective answers are added to the mistake book (Req 9.1)."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        # Reading answer "C" is wrong
        sheet = _make_answer_sheet(reading_answer="C")

        service.grade_and_report(sheet, paper)

        # The wrong reading question should be in the mistake book
        assert "2024-12-set1-reading-careful-01" in mistake_repo.entries
        entry = mistake_repo.entries["2024-12-set1-reading-careful-01"]
        assert entry.error_count == 1

    def test_correct_answers_not_in_mistake_book(self) -> None:
        """Correct answers are NOT added to the mistake book."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        # Both objective answers correct
        sheet = _make_answer_sheet(listening_answer="A", reading_answer="B")

        service.grade_and_report(sheet, paper)

        # Correct answers should not be in the mistake book
        assert "2024-12-set1-listening-news-01" not in mistake_repo.entries
        assert "2024-12-set1-reading-careful-01" not in mistake_repo.entries

    def test_low_score_subjective_added_to_mistake_book(self) -> None:
        """Subjective questions with earned < 60% of max go to mistake book (Req 9.2)."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        # Low rubric: total = 1+1+1+1 = 4; earned = 4/20 * 15 = 3.00
        # Threshold = 15 * 0.6 = 9.00; 3.00 < 9.00 → mistake book
        rubric = RubricScore(content=1, structure=1, language=1, word_count=1)
        sheet = _make_answer_sheet(writing_rubric=rubric)

        service.grade_and_report(sheet, paper)

        assert "2024-12-set1-writing-01" in mistake_repo.entries

    def test_high_score_subjective_not_in_mistake_book(self) -> None:
        """Subjective questions with earned >= 60% of max stay out of mistake book."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        # High rubric: total = 5+5+5+5 = 20; earned = 20/20 * 15 = 15.00
        # Threshold = 15 * 0.6 = 9.00; 15.00 >= 9.00 → no mistake book
        rubric = RubricScore(content=5, structure=5, language=5, word_count=5)
        sheet = _make_answer_sheet(writing_rubric=rubric)

        service.grade_and_report(sheet, paper)

        assert "2024-12-set1-writing-01" not in mistake_repo.entries

    def test_report_counts_are_consistent(self) -> None:
        """correct + wrong + unanswered == total questions (Req 8.1)."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet()

        report = service.grade_and_report(sheet, paper)

        total = report.correct_count + report.wrong_count + report.unanswered_count
        assert total == len(report.grades)

    def test_report_has_scaled_score_710(self) -> None:
        """ScoreReport includes a valid 710-scale score (Req 6.4)."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet()

        report = service.grade_and_report(sheet, paper)

        assert 0 <= report.scaled_score_710 <= 710


class TestSubmitManualRubric:
    """Tests for GradingService.submit_manual_rubric."""

    def test_recalculates_report_on_rubric_submission(self) -> None:
        """Submitting a rubric recalculates the ScoreReport (Req 7.6)."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        # First: grade without rubric
        sheet = _make_answer_sheet(writing_rubric=None)
        initial_report = service.grade_and_report(sheet, paper)

        # Now submit a rubric
        rubric = RubricScore(content=4, structure=4, language=4, word_count=4)
        updated_report = service.submit_manual_rubric(
            question_id="2024-12-set1-writing-01",
            rubric=rubric,
            paper=paper,
            sheet=sheet,
            existing_report=initial_report,
        )

        # The writing question should now be graded
        writing_grade = next(
            g for g in updated_report.grades
            if g.question_id == "2024-12-set1-writing-01"
        )
        assert writing_grade.status == "ok"
        # total = 16; earned = 16/20 * 15 = 12.00
        assert writing_grade.earned_score == Decimal("12.00")

    def test_rubric_submission_persists_updated_report(self) -> None:
        """Rubric submission saves the updated report to the repository."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet(writing_rubric=None)
        initial_report = service.grade_and_report(sheet, paper)

        rubric = RubricScore(content=3, structure=3, language=3, word_count=3)
        service.submit_manual_rubric(
            question_id="2024-12-set1-writing-01",
            rubric=rubric,
            paper=paper,
            sheet=sheet,
            existing_report=initial_report,
        )

        # Two reports saved: initial + updated
        assert len(repo.reports) == 2

    def test_rubric_submission_updates_mistake_book(self) -> None:
        """Low-score rubric submission adds to mistake book (Req 9.2)."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet(writing_rubric=None)
        initial_report = service.grade_and_report(sheet, paper)

        # Low rubric: total = 2+1+1+1 = 5; earned = 5/20 * 15 = 3.75
        # Threshold = 15 * 0.6 = 9.00; 3.75 < 9.00 → mistake book
        rubric = RubricScore(content=2, structure=1, language=1, word_count=1)
        service.submit_manual_rubric(
            question_id="2024-12-set1-writing-01",
            rubric=rubric,
            paper=paper,
            sheet=sheet,
            existing_report=initial_report,
        )

        assert "2024-12-set1-writing-01" in mistake_repo.entries

    def test_nonexistent_question_returns_existing_report(self) -> None:
        """Submitting rubric for a non-existent question returns the existing report."""
        repo = FakeScoreReportRepo()
        mistake_repo = FakeMistakeRepo()
        service = GradingService(repo, mistake_repo)

        paper = _make_paper_with_questions()
        sheet = _make_answer_sheet(writing_rubric=None)
        initial_report = service.grade_and_report(sheet, paper)

        rubric = RubricScore(content=3, structure=3, language=3, word_count=3)
        result = service.submit_manual_rubric(
            question_id="nonexistent-question-id",
            rubric=rubric,
            paper=paper,
            sheet=sheet,
            existing_report=initial_report,
        )

        # Should return the existing report unchanged
        assert result is initial_report
