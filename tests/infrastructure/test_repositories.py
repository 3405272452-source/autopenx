"""Integration tests for all repository implementations.

Tests cover:
- CRUD operations for all repositories (paper_repo, answer_sheet_repo,
  score_report_repo, mistake_repo, plan_repo, log_repo)
- Foreign key cascade deletes (answer_sheet -> answer, score_report -> question_grade,
  study_plan -> study_day -> study_task)
- AI grading history trimming to max 5 entries per question (Req 15.12)

Uses a temporary SQLite file (tmp_path fixture) for each test to ensure
isolation and reproducibility.

Requirements: 12.1, 12.2, 15.12
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine

from cet4_app.domain.enums import (
    AudioStatus,
    DayStatus,
    PaperStatus,
    QuestionType,
    SectionName,
    SessionMode,
    SheetStatus,
    TaskKind,
)
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet, RubricScore
from cet4_app.domain.models.mistake_entry import MistakeEntry
from cet4_app.domain.models.paper_set import PaperSet
from cet4_app.domain.models.question import (
    AudioRange,
    Paper,
    Question,
    Section,
    SubSection,
)
from cet4_app.domain.models.score_report import QuestionGrade, ScoreReport
from cet4_app.domain.models.study_plan import (
    PlanParams,
    StudyDay,
    StudyPlan,
    StudyTask,
)
from cet4_app.infrastructure.persistence.db import create_engine, init_schema, transaction
from cet4_app.infrastructure.repositories.answer_sheet_repo import AnswerSheetRepository
from cet4_app.infrastructure.repositories.log_repo import LogRepo
from cet4_app.infrastructure.repositories.mistake_repo import MistakeRepo
from cet4_app.infrastructure.repositories.paper_repo import PaperRepo
from cet4_app.infrastructure.repositories.plan_repo import PlanRepo
from cet4_app.infrastructure.repositories.score_report_repo import ScoreReportRepo


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    """Create a fresh SQLite engine with schema initialized for each test."""
    db_path = tmp_path / "test_repos.db"
    eng = create_engine(db_path)
    init_schema(eng)
    return eng


@pytest.fixture
def paper_repo(engine: Engine) -> PaperRepo:
    return PaperRepo(engine)


@pytest.fixture
def answer_sheet_repo(engine: Engine) -> AnswerSheetRepository:
    return AnswerSheetRepository(engine)


@pytest.fixture
def score_report_repo(engine: Engine) -> ScoreReportRepo:
    return ScoreReportRepo(engine)


@pytest.fixture
def mistake_repo(engine: Engine) -> MistakeRepo:
    return MistakeRepo(engine)


@pytest.fixture
def plan_repo(engine: Engine) -> PlanRepo:
    return PlanRepo(engine)


@pytest.fixture
def log_repo(engine: Engine) -> LogRepo:
    return LogRepo(engine)


# ===========================================================================
# Helpers — create domain objects for testing
# ===========================================================================


def _uid() -> str:
    return str(uuid.uuid4())[:8]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_paper_set(paper_set_id: str = "ps-2024-12") -> PaperSet:
    return PaperSet(
        paper_set_id=paper_set_id,
        exam_period="2024-12",
        directory_name="2024年12月CET4真题",
        scanned_at=_now(),
    )


def _make_paper(paper_id: str = "2024-12-set1", paper_set_id: str = "ps-2024-12") -> Paper:
    return Paper(
        paper_id=paper_id,
        paper_set_id=paper_set_id,
        exam_period="2024-12",
        set_index=1,
        paper_pdf_path="C:/cet4/paper.pdf",
        answer_pdf_path="C:/cet4/answer.pdf",
        audio_mp3_path="C:/cet4/audio.mp3",
        audio_status=AudioStatus.available,
        status=PaperStatus.ok,
        sections=[],
        shared_banked_words=[],
        long_reading_paragraphs={},
    )


def _make_question(
    question_id: str = "q-01",
    paper_id: str = "2024-12-set1",
) -> Question:
    return Question(
        id=question_id,
        paper_id=paper_id,
        section=SectionName.listening,
        sub_section="news",
        question_type=QuestionType.listening_news,
        prompt="What happened?",
        options=["A text", "B text", "C text", "D text"],
        correct_letter="A",
        reference_answer="A",
        explanation="Because A.",
        score=Decimal("7.10"),
        tags=["vocabulary"],
        audio_range=AudioRange(start_s=10.0, end_s=30.0),
    )


def _setup_paper_with_questions(
    paper_repo: PaperRepo, paper_id: str = "2024-12-set1", n_questions: int = 3
) -> list[Question]:
    """Create paper_set, paper, and n questions. Returns the questions."""
    paper_repo.save_paper_set(_make_paper_set())
    paper_repo.save_paper(_make_paper(paper_id))
    questions = [_make_question(f"q-{i:02d}", paper_id) for i in range(1, n_questions + 1)]
    paper_repo.save_questions(questions)
    return questions


def _make_answer_sheet(
    sheet_id: str = "sheet-01",
    paper_id: str = "2024-12-set1",
    question_ids: list[str] | None = None,
) -> AnswerSheet:
    now = _now()
    answers: dict[str, Answer] = {}
    for qid in (question_ids or []):
        answers[qid] = Answer(
            question_id=qid,
            user_answer="A",
            last_updated_at=now,
        )
    return AnswerSheet(
        sheet_id=sheet_id,
        paper_id=paper_id,
        status=SheetStatus.in_progress,
        mode=SessionMode.practice,
        started_at=now,
        elapsed_seconds=120,
        answers=answers,
        updated_at=now,
    )


def _make_score_report(
    report_id: str = "report-01",
    sheet_id: str = "sheet-01",
    paper_id: str = "2024-12-set1",
    question_ids: list[str] | None = None,
) -> ScoreReport:
    grades = []
    for qid in (question_ids or ["q-01"]):
        grades.append(
            QuestionGrade(
                question_id=qid,
                is_correct=True,
                status="ok",
                earned_score=Decimal("7.10"),
                score_max=Decimal("7.10"),
                reference_answer="A",
                user_answer="A",
            )
        )
    return ScoreReport(
        report_id=report_id,
        sheet_id=sheet_id,
        paper_id=paper_id,
        total_score=Decimal("85.50"),
        scaled_score_710=500,
        section_scores={SectionName.listening: Decimal("90.00")},
        grades=grades,
        correct_count=1,
        wrong_count=0,
        unanswered_count=0,
        cannot_grade_ids=[],
        duration_seconds=3600,
        generated_at=_now(),
    )


def _make_mistake_entry(
    entry_id: str | None = None,
    question_id: str = "q-01",
    paper_id: str = "2024-12-set1",
) -> MistakeEntry:
    now = _now()
    return MistakeEntry(
        entry_id=entry_id or _uid(),
        question_id=question_id,
        paper_id=paper_id,
        first_wrong_at=now,
        last_wrong_at=now,
        error_count=1,
        redo_count=0,
        correct_streak=0,
        mastered=False,
        notes="Test note",
        tags=["vocabulary"],
    )


def _make_study_plan(plan_id: str = "plan-01") -> StudyPlan:
    start = date.today()
    params = PlanParams(
        start_date=start,
        daily_minutes_cap=120,
        section_ratio={
            SectionName.writing: 15,
            SectionName.listening: 35,
            SectionName.reading: 35,
            SectionName.translation: 15,
        },
    )
    days = []
    for i in range(1, 4):  # 3 days for testing
        tasks = [
            StudyTask(
                task_id=f"{plan_id}-day{i}-task1",
                kind=TaskKind.paper,
                paper_id="2024-12-set1",
                section=SectionName.listening,
                mistakes_to_review=0,
                intensive_listening_minutes=30,
                writing_translation_count=0,
                completed=False,
            )
        ]
        days.append(
            StudyDay(
                day_index=i,
                date=start + timedelta(days=i - 1),
                tasks=tasks,
                status=DayStatus.pending,
                daily_target_accuracy=0.8,
            )
        )
    return StudyPlan(
        plan_id=plan_id,
        start_date=start,
        total_days=3,
        params=params,
        days=days,
    )


# ===========================================================================
# Tests: PaperRepo CRUD
# ===========================================================================


class TestPaperRepoCRUD:
    """Test CRUD operations for PaperRepo (paper_set, paper, question)."""

    def test_save_and_load_paper_set(self, paper_repo: PaperRepo):
        ps = _make_paper_set()
        paper_repo.save_paper_set(ps)

        loaded = paper_repo.load_paper_set_by_id(ps.paper_set_id)
        assert loaded is not None
        assert loaded.paper_set_id == ps.paper_set_id
        assert loaded.exam_period == ps.exam_period
        assert loaded.directory_name == ps.directory_name

    def test_load_all_paper_sets(self, paper_repo: PaperRepo):
        ps1 = _make_paper_set("ps-2023-12")
        ps2 = _make_paper_set("ps-2024-06")
        paper_repo.save_paper_set(ps1)
        paper_repo.save_paper_set(ps2)

        all_sets = paper_repo.load_all_paper_sets()
        assert len(all_sets) == 2

    def test_save_and_load_paper(self, paper_repo: PaperRepo):
        paper_repo.save_paper_set(_make_paper_set())
        paper = _make_paper()
        paper_repo.save_paper(paper)

        loaded = paper_repo.load_paper_by_id(paper.paper_id)
        assert loaded is not None
        assert loaded.paper_id == paper.paper_id
        assert loaded.set_index == paper.set_index
        assert loaded.audio_status == AudioStatus.available
        assert loaded.status == PaperStatus.ok

    def test_save_and_load_questions(self, paper_repo: PaperRepo):
        questions = _setup_paper_with_questions(paper_repo)

        loaded = paper_repo.load_questions_by_paper("2024-12-set1")
        assert len(loaded) == 3
        # Verify question fields round-trip
        q = loaded[0]
        assert q.section == SectionName.listening
        assert q.question_type == QuestionType.listening_news
        assert q.options == ["A text", "B text", "C text", "D text"]
        assert q.audio_range is not None
        assert q.audio_range.start_s == 10.0
        assert q.audio_range.end_s == 30.0
        assert q.score == Decimal("7.10")
        assert q.tags == ["vocabulary"]

    def test_save_paper_with_questions(self, paper_repo: PaperRepo):
        paper_repo.save_paper_set(_make_paper_set())
        q1 = _make_question("q-01")
        q2 = _make_question("q-02")
        paper = Paper(
            paper_id="2024-12-set1",
            paper_set_id="ps-2024-12",
            exam_period="2024-12",
            set_index=1,
            paper_pdf_path="C:/cet4/paper.pdf",
            answer_pdf_path="C:/cet4/answer.pdf",
            audio_mp3_path="C:/cet4/audio.mp3",
            audio_status=AudioStatus.available,
            status=PaperStatus.ok,
            sections=[
                Section(
                    name=SectionName.listening,
                    sub_sections=[SubSection(name="news", questions=[q1, q2])],
                    status=PaperStatus.ok,
                )
            ],
            shared_banked_words=[],
            long_reading_paragraphs={},
        )
        paper_repo.save_paper_with_questions(paper)

        loaded = paper_repo.load_paper_by_id("2024-12-set1")
        assert loaded is not None
        # Questions should be reconstructed into sections
        all_questions = paper_repo.load_questions_by_paper("2024-12-set1")
        assert len(all_questions) == 2

    def test_delete_paper_removes_questions(self, paper_repo: PaperRepo):
        _setup_paper_with_questions(paper_repo)
        # Verify questions exist
        assert len(paper_repo.load_questions_by_paper("2024-12-set1")) == 3

        paper_repo.delete_paper("2024-12-set1")

        # Paper and questions should be gone
        assert paper_repo.load_paper_by_id("2024-12-set1") is None
        assert paper_repo.load_questions_by_paper("2024-12-set1") == []

    def test_load_nonexistent_paper_returns_none(self, paper_repo: PaperRepo):
        assert paper_repo.load_paper_by_id("nonexistent") is None

    def test_load_question_by_id(self, paper_repo: PaperRepo):
        _setup_paper_with_questions(paper_repo)
        q = paper_repo.load_question_by_id("q-01")
        assert q is not None
        assert q.id == "q-01"

    def test_load_questions_by_type(self, paper_repo: PaperRepo):
        _setup_paper_with_questions(paper_repo)
        qs = paper_repo.load_questions_by_type(QuestionType.listening_news)
        assert len(qs) == 3


# ===========================================================================
# Tests: AnswerSheetRepository CRUD
# ===========================================================================


class TestAnswerSheetRepoCRUD:
    """Test CRUD operations for AnswerSheetRepository."""

    def test_save_and_load_sheet(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository):
        questions = _setup_paper_with_questions(paper_repo)
        qids = [q.id for q in questions]
        sheet = _make_answer_sheet(question_ids=qids)

        answer_sheet_repo.save_sheet(sheet)
        loaded = answer_sheet_repo.load_sheet_by_id("sheet-01")

        assert loaded is not None
        assert loaded.sheet_id == "sheet-01"
        assert loaded.paper_id == "2024-12-set1"
        assert loaded.status == SheetStatus.in_progress
        assert loaded.mode == SessionMode.practice
        assert loaded.elapsed_seconds == 120
        assert len(loaded.answers) == 3
        assert "q-01" in loaded.answers
        assert loaded.answers["q-01"].user_answer == "A"

    def test_update_sheet_status(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository):
        _setup_paper_with_questions(paper_repo)
        sheet = _make_answer_sheet(question_ids=["q-01"])
        answer_sheet_repo.save_sheet(sheet)

        now = _now()
        result = answer_sheet_repo.update_sheet_status(
            "sheet-01", SheetStatus.submitted, submitted_at=now
        )
        assert result is True

        loaded = answer_sheet_repo.load_sheet_by_id("sheet-01")
        assert loaded is not None
        assert loaded.status == SheetStatus.submitted
        assert loaded.submitted_at is not None

    def test_save_draft(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository):
        _setup_paper_with_questions(paper_repo)
        sheet = _make_answer_sheet(question_ids=["q-01"])
        answer_sheet_repo.save_sheet(sheet)

        # Modify the answer and save as draft
        sheet.answers["q-01"] = Answer(
            question_id="q-01",
            user_answer="B",
            last_updated_at=_now(),
        )
        sheet.elapsed_seconds = 200
        answer_sheet_repo.save_draft(sheet)

        loaded = answer_sheet_repo.load_sheet_by_id("sheet-01")
        assert loaded is not None
        assert loaded.answers["q-01"].user_answer == "B"
        assert loaded.elapsed_seconds == 200
        assert loaded.draft_saved_at is not None

    def test_load_latest_draft(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository):
        _setup_paper_with_questions(paper_repo)
        sheet = _make_answer_sheet(question_ids=["q-01"])
        answer_sheet_repo.save_sheet(sheet)
        answer_sheet_repo.save_draft(sheet)

        draft = answer_sheet_repo.load_latest_draft("2024-12-set1")
        assert draft is not None
        assert draft.sheet_id == "sheet-01"

    def test_load_nonexistent_sheet_returns_none(self, answer_sheet_repo: AnswerSheetRepository):
        assert answer_sheet_repo.load_sheet_by_id("nonexistent") is None

    def test_sheet_with_rubric(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository):
        _setup_paper_with_questions(paper_repo)
        now = _now()
        rubric = RubricScore(content=4, structure=3, language=5, word_count=4)
        sheet = AnswerSheet(
            sheet_id="sheet-rubric",
            paper_id="2024-12-set1",
            status=SheetStatus.in_progress,
            mode=SessionMode.practice,
            started_at=now,
            elapsed_seconds=60,
            answers={
                "q-01": Answer(
                    question_id="q-01",
                    user_answer="My essay text",
                    last_updated_at=now,
                    rubric=rubric,
                )
            },
            updated_at=now,
        )
        answer_sheet_repo.save_sheet(sheet)

        loaded = answer_sheet_repo.load_sheet_by_id("sheet-rubric")
        assert loaded is not None
        assert loaded.answers["q-01"].rubric is not None
        assert loaded.answers["q-01"].rubric.content == 4
        assert loaded.answers["q-01"].rubric.language == 5


# ===========================================================================
# Tests: ScoreReportRepo CRUD
# ===========================================================================


class TestScoreReportRepoCRUD:
    """Test CRUD operations for ScoreReportRepo."""

    def test_save_and_load_report(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository, score_report_repo: ScoreReportRepo):
        questions = _setup_paper_with_questions(paper_repo)
        sheet = _make_answer_sheet(question_ids=["q-01"])
        answer_sheet_repo.save_sheet(sheet)

        report = _make_score_report(question_ids=["q-01"])
        score_report_repo.save_report(report)

        loaded = score_report_repo.load_report_by_id("report-01")
        assert loaded is not None
        assert loaded.report_id == "report-01"
        assert loaded.total_score == Decimal("85.50")
        assert loaded.scaled_score_710 == 500
        assert loaded.correct_count == 1
        assert loaded.wrong_count == 0
        assert loaded.unanswered_count == 0
        assert len(loaded.grades) == 1
        assert loaded.grades[0].question_id == "q-01"
        assert loaded.grades[0].is_correct is True
        assert loaded.grades[0].earned_score == Decimal("7.10")

    def test_load_report_by_sheet_id(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository, score_report_repo: ScoreReportRepo):
        _setup_paper_with_questions(paper_repo)
        sheet = _make_answer_sheet(question_ids=["q-01"])
        answer_sheet_repo.save_sheet(sheet)

        report = _make_score_report(question_ids=["q-01"])
        score_report_repo.save_report(report)

        loaded = score_report_repo.load_report_by_sheet_id("sheet-01")
        assert loaded is not None
        assert loaded.report_id == "report-01"

    def test_list_reports_by_paper(self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository, score_report_repo: ScoreReportRepo):
        _setup_paper_with_questions(paper_repo)
        # Create two sheets and reports
        sheet1 = _make_answer_sheet("sheet-01", question_ids=["q-01"])
        sheet2 = _make_answer_sheet("sheet-02", question_ids=["q-01"])
        answer_sheet_repo.save_sheet(sheet1)
        answer_sheet_repo.save_sheet(sheet2)

        r1 = _make_score_report("report-01", "sheet-01", question_ids=["q-01"])
        r2 = _make_score_report("report-02", "sheet-02", question_ids=["q-01"])
        score_report_repo.save_report(r1)
        score_report_repo.save_report(r2)

        reports = score_report_repo.list_reports_by_paper("2024-12-set1")
        assert len(reports) == 2

    def test_load_nonexistent_report_returns_none(self, score_report_repo: ScoreReportRepo):
        assert score_report_repo.load_report_by_id("nonexistent") is None


# ===========================================================================
# Tests: MistakeRepo CRUD
# ===========================================================================


class TestMistakeRepoCRUD:
    """Test CRUD operations for MistakeRepo."""

    def test_save_and_load_entry(self, paper_repo: PaperRepo, mistake_repo: MistakeRepo):
        _setup_paper_with_questions(paper_repo)
        entry = _make_mistake_entry(entry_id="me-01", question_id="q-01")
        mistake_repo.save_entry(entry)

        loaded = mistake_repo.load_by_id("me-01")
        assert loaded is not None
        assert loaded.entry_id == "me-01"
        assert loaded.question_id == "q-01"
        assert loaded.error_count == 1
        assert loaded.mastered is False
        assert loaded.notes == "Test note"
        assert loaded.tags == ["vocabulary"]

    def test_update_entry(self, paper_repo: PaperRepo, mistake_repo: MistakeRepo):
        _setup_paper_with_questions(paper_repo)
        entry = _make_mistake_entry(entry_id="me-01", question_id="q-01")
        mistake_repo.save_entry(entry)

        # Update fields (mastered=True requires correct_streak >= 2 per Req 9.6)
        entry.error_count = 3
        entry.correct_streak = 2
        entry.mastered = True
        entry.notes = "Updated note"
        mistake_repo.update_entry(entry)

        loaded = mistake_repo.load_by_id("me-01")
        assert loaded is not None
        assert loaded.error_count == 3
        assert loaded.mastered is True
        assert loaded.correct_streak == 2
        assert loaded.notes == "Updated note"

    def test_load_by_question_id(self, paper_repo: PaperRepo, mistake_repo: MistakeRepo):
        _setup_paper_with_questions(paper_repo)
        entry = _make_mistake_entry(entry_id="me-01", question_id="q-01")
        mistake_repo.save_entry(entry)

        loaded = mistake_repo.load_by_question_id("q-01")
        assert loaded is not None
        assert loaded.entry_id == "me-01"

    def test_delete_entry(self, paper_repo: PaperRepo, mistake_repo: MistakeRepo):
        _setup_paper_with_questions(paper_repo)
        entry = _make_mistake_entry(entry_id="me-01", question_id="q-01")
        mistake_repo.save_entry(entry)

        result = mistake_repo.delete_entry("me-01")
        assert result is True
        assert mistake_repo.load_by_id("me-01") is None

    def test_filter_entries_by_mastered(self, paper_repo: PaperRepo, mistake_repo: MistakeRepo):
        _setup_paper_with_questions(paper_repo)
        e1 = _make_mistake_entry(entry_id="me-01", question_id="q-01")
        e2 = MistakeEntry(
            entry_id="me-02",
            question_id="q-02",
            paper_id="2024-12-set1",
            first_wrong_at=_now(),
            last_wrong_at=_now(),
            error_count=1,
            redo_count=2,
            correct_streak=2,
            mastered=True,
            notes="Mastered",
            tags=["vocabulary"],
        )
        mistake_repo.save_entry(e1)
        mistake_repo.save_entry(e2)

        from cet4_app.infrastructure.repositories.mistake_repo import MistakeQuery

        # Filter for non-mastered
        results = mistake_repo.filter_entries(MistakeQuery(mastered=False))
        assert len(results) == 1
        assert results[0].entry_id == "me-01"

        # Filter for mastered
        results = mistake_repo.filter_entries(MistakeQuery(mastered=True))
        assert len(results) == 1
        assert results[0].entry_id == "me-02"

    def test_bulk_import(self, paper_repo: PaperRepo, mistake_repo: MistakeRepo):
        _setup_paper_with_questions(paper_repo)
        entries = [
            _make_mistake_entry(entry_id="me-01", question_id="q-01"),
            _make_mistake_entry(entry_id="me-02", question_id="q-02"),
        ]
        count = mistake_repo.bulk_import(entries)
        assert count == 2

    def test_load_nonexistent_returns_none(self, mistake_repo: MistakeRepo):
        assert mistake_repo.load_by_id("nonexistent") is None


# ===========================================================================
# Tests: PlanRepo CRUD
# ===========================================================================


class TestPlanRepoCRUD:
    """Test CRUD operations for PlanRepo."""

    def test_save_and_load_plan(self, paper_repo: PaperRepo, plan_repo: PlanRepo):
        # Plan references paper_id in tasks, so we need the paper to exist
        _setup_paper_with_questions(paper_repo)
        plan = _make_study_plan()
        plan_repo.save_plan(plan)

        loaded = plan_repo.load_plan_by_id("plan-01")
        assert loaded is not None
        assert loaded.plan_id == "plan-01"
        assert loaded.total_days == 3
        assert len(loaded.days) == 3
        assert loaded.days[0].day_index == 1
        assert loaded.days[0].status == DayStatus.pending
        assert loaded.days[0].daily_target_accuracy == 0.8
        assert len(loaded.days[0].tasks) == 1
        assert loaded.days[0].tasks[0].kind == TaskKind.paper
        assert loaded.days[0].tasks[0].intensive_listening_minutes == 30

    def test_load_active_plan(self, paper_repo: PaperRepo, plan_repo: PlanRepo):
        _setup_paper_with_questions(paper_repo)
        plan = _make_study_plan()
        plan_repo.save_plan(plan)

        active = plan_repo.load_active_plan()
        assert active is not None
        assert active.plan_id == "plan-01"

    def test_update_day_status(self, paper_repo: PaperRepo, plan_repo: PlanRepo):
        _setup_paper_with_questions(paper_repo)
        plan = _make_study_plan()
        plan_repo.save_plan(plan)

        result = plan_repo.update_day_status("plan-01", 1, DayStatus.completed)
        assert result is True

        loaded = plan_repo.load_plan_by_id("plan-01")
        assert loaded is not None
        assert loaded.days[0].status == DayStatus.completed

    def test_delete_plan(self, paper_repo: PaperRepo, plan_repo: PlanRepo):
        _setup_paper_with_questions(paper_repo)
        plan = _make_study_plan()
        plan_repo.save_plan(plan)

        result = plan_repo.delete_plan("plan-01")
        assert result is True
        assert plan_repo.load_plan_by_id("plan-01") is None

    def test_load_nonexistent_plan_returns_none(self, plan_repo: PlanRepo):
        assert plan_repo.load_plan_by_id("nonexistent") is None


# ===========================================================================
# Tests: LogRepo CRUD
# ===========================================================================


class TestLogRepoCRUD:
    """Test CRUD operations for LogRepo (app_log and ai_grading_log)."""

    def test_insert_and_query_app_log(self, log_repo: LogRepo):
        log_id = log_repo.insert_log("INFO", "Test message", "parser")
        assert log_id is not None

        logs = log_repo.query_logs()
        assert len(logs) == 1
        assert logs[0]["level"] == "INFO"
        assert logs[0]["message"] == "Test message"
        assert logs[0]["category"] == "parser"

    def test_query_logs_with_level_filter(self, log_repo: LogRepo):
        log_repo.insert_log("INFO", "Info msg", "parser")
        log_repo.insert_log("ERROR", "Error msg", "grader")

        errors = log_repo.query_logs(level_filter="ERROR")
        assert len(errors) == 1
        assert errors[0]["level"] == "ERROR"

    def test_clear_all_logs(self, log_repo: LogRepo):
        log_repo.insert_log("INFO", "msg1", "parser")
        log_repo.insert_log("WARN", "msg2", "audio")

        count = log_repo.clear_all_logs()
        assert count == 2
        assert log_repo.query_logs() == []

    def test_insert_and_query_grading_log(self, log_repo: LogRepo):
        log_id = log_repo.insert_grading_log(
            question_id="q-01",
            model="deepseek-v4-flash",
            http_status=200,
            duration_ms=1500,
            prompt_tokens=100,
            completion_tokens=50,
            from_cache=False,
            context_truncated=True,
        )
        assert log_id is not None

        logs = log_repo.query_grading_logs(question_id="q-01")
        assert len(logs) == 1
        assert logs[0]["model"] == "deepseek-v4-flash"
        assert logs[0]["http_status"] == 200
        assert logs[0]["from_cache"] is False
        assert logs[0]["context_truncated"] is True

    def test_cleanup_old_logs(self, log_repo: LogRepo, engine: Engine):
        # Insert a log with a timestamp 31 days ago
        old_time = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO app_log (log_id, level, category, message, created_at) "
                    "VALUES (:log_id, :level, :category, :message, :created_at)"
                ),
                {
                    "log_id": "old-log",
                    "level": "INFO",
                    "category": "test",
                    "message": "Old message",
                    "created_at": old_time,
                },
            )
        # Insert a recent log
        log_repo.insert_log("INFO", "Recent message", "test")

        # Cleanup should remove the old log
        deleted = log_repo.cleanup_old_logs(days=30)
        assert deleted >= 1

        # Recent log should remain
        logs = log_repo.query_logs()
        assert len(logs) == 1
        assert logs[0]["message"] == "Recent message"


# ===========================================================================
# Tests: Foreign Key Cascade Deletes
# ===========================================================================


class TestForeignKeyCascade:
    """Test that FK cascade deletes work correctly across related tables."""

    def test_delete_answer_sheet_cascades_to_answers(
        self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository, engine: Engine
    ):
        """Deleting an answer_sheet should cascade-delete its answer rows."""
        _setup_paper_with_questions(paper_repo)
        sheet = _make_answer_sheet(question_ids=["q-01", "q-02"])
        answer_sheet_repo.save_sheet(sheet)

        # Verify answers exist
        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM answer WHERE sheet_id = 'sheet-01'")
            ).scalar()
            assert count == 2

        # Delete the sheet directly via SQL (simulating cascade)
        with transaction(engine) as conn:
            conn.execute(text("DELETE FROM answer_sheet WHERE sheet_id = 'sheet-01'"))

        # Answers should be cascade-deleted
        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM answer WHERE sheet_id = 'sheet-01'")
            ).scalar()
            assert count == 0

    def test_delete_score_report_cascades_to_question_grades(
        self, paper_repo: PaperRepo, answer_sheet_repo: AnswerSheetRepository,
        score_report_repo: ScoreReportRepo, engine: Engine
    ):
        """Deleting a score_report should cascade-delete its question_grade rows."""
        _setup_paper_with_questions(paper_repo)
        sheet = _make_answer_sheet(question_ids=["q-01"])
        answer_sheet_repo.save_sheet(sheet)
        report = _make_score_report(question_ids=["q-01"])
        score_report_repo.save_report(report)

        # Verify grades exist
        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM question_grade WHERE report_id = 'report-01'")
            ).scalar()
            assert count == 1

        # Delete the report directly via SQL
        with transaction(engine) as conn:
            conn.execute(text("DELETE FROM score_report WHERE report_id = 'report-01'"))

        # Grades should be cascade-deleted
        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM question_grade WHERE report_id = 'report-01'")
            ).scalar()
            assert count == 0

    def test_delete_study_plan_cascades_to_days_and_tasks(
        self, paper_repo: PaperRepo, plan_repo: PlanRepo, engine: Engine
    ):
        """Deleting a study_plan should cascade-delete study_day and study_task rows."""
        _setup_paper_with_questions(paper_repo)
        plan = _make_study_plan()
        plan_repo.save_plan(plan)

        # Verify days and tasks exist
        with engine.connect() as conn:
            day_count = conn.execute(
                text("SELECT COUNT(*) FROM study_day WHERE plan_id = 'plan-01'")
            ).scalar()
            task_count = conn.execute(
                text("SELECT COUNT(*) FROM study_task WHERE plan_id = 'plan-01'")
            ).scalar()
            assert day_count == 3
            assert task_count == 3

        # Delete the plan
        plan_repo.delete_plan("plan-01")

        # Days and tasks should be gone
        with engine.connect() as conn:
            day_count = conn.execute(
                text("SELECT COUNT(*) FROM study_day WHERE plan_id = 'plan-01'")
            ).scalar()
            task_count = conn.execute(
                text("SELECT COUNT(*) FROM study_task WHERE plan_id = 'plan-01'")
            ).scalar()
            assert day_count == 0
            assert task_count == 0


# ===========================================================================
# Tests: AI Grading History Trimming (Req 15.12)
# ===========================================================================


class TestAIGradingHistoryTrimming:
    """Test that ai_grading_history is trimmed to max 5 entries per question.

    The schema defines a trigger (trg_ai_grading_history_limit) that fires
    AFTER INSERT on ai_grading_history and deletes entries beyond the 5 most
    recent for the same question_id.
    """

    def test_history_trimmed_to_5_entries(self, paper_repo: PaperRepo, engine: Engine):
        """Inserting more than 5 history entries for one question keeps only 5."""
        _setup_paper_with_questions(paper_repo)

        # We need an answer_sheet for the ai_grading_result FK
        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO answer_sheet "
                    "(sheet_id, paper_id, status, mode, started_at, elapsed_seconds, updated_at) "
                    "VALUES ('sheet-ai', '2024-12-set1', 'submitted', 'practice', "
                    ":now, 100, :now)"
                ),
                {"now": _now().isoformat()},
            )

        base_time = datetime(2024, 1, 1, tzinfo=timezone.utc)

        # Insert 7 ai_grading_result entries and corresponding history entries
        for i in range(1, 8):
            result_id = f"result-{i:02d}"
            gen_time = (base_time + timedelta(hours=i)).isoformat()
            expires_at = (base_time + timedelta(days=7, hours=i)).isoformat()

            with transaction(engine) as conn:
                # Insert the ai_grading_result row
                conn.execute(
                    text(
                        "INSERT INTO ai_grading_result "
                        "(result_id, question_id, sheet_id, model, input_fingerprint, "
                        "dimension_scores_json, overall_score, comments_json, "
                        "highlights_json, issues_json, revised_version, "
                        "context_truncated, generated_at, expires_at) "
                        "VALUES (:result_id, 'q-01', 'sheet-ai', 'deepseek-v4-flash', "
                        ":fingerprint, :dim_scores, 85.0, :comments, "
                        "'[]', '[]', 'Revised text here for testing purposes.', "
                        "0, :gen_time, :expires_at)"
                    ),
                    {
                        "result_id": result_id,
                        "fingerprint": f"fp-{i:02d}",
                        "dim_scores": '{"content":4,"structure":4,"language":4,"word_count":4}',
                        "comments": '{"content":"Good","structure":"OK","language":"Fine","word_count":"OK"}',
                        "gen_time": gen_time,
                        "expires_at": expires_at,
                    },
                )

                # Insert the history entry (trigger fires after this)
                conn.execute(
                    text(
                        "INSERT INTO ai_grading_history "
                        "(history_id, question_id, result_id, generated_at) "
                        "VALUES (:history_id, 'q-01', :result_id, :gen_time)"
                    ),
                    {
                        "history_id": f"hist-{i:02d}",
                        "result_id": result_id,
                        "gen_time": gen_time,
                    },
                )

        # Verify: only 5 history entries should remain for q-01
        with engine.connect() as conn:
            count = conn.execute(
                text(
                    "SELECT COUNT(*) FROM ai_grading_history "
                    "WHERE question_id = 'q-01'"
                )
            ).scalar()
            assert count == 5

            # The 5 most recent should be kept (result-03 through result-07)
            rows = conn.execute(
                text(
                    "SELECT result_id FROM ai_grading_history "
                    "WHERE question_id = 'q-01' "
                    "ORDER BY generated_at ASC"
                )
            ).fetchall()
            result_ids = [r[0] for r in rows]
            assert result_ids == [
                "result-03", "result-04", "result-05", "result-06", "result-07"
            ]

    def test_history_under_limit_not_trimmed(self, paper_repo: PaperRepo, engine: Engine):
        """Inserting 3 history entries (under limit) keeps all 3."""
        _setup_paper_with_questions(paper_repo)

        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO answer_sheet "
                    "(sheet_id, paper_id, status, mode, started_at, elapsed_seconds, updated_at) "
                    "VALUES ('sheet-ai2', '2024-12-set1', 'submitted', 'practice', "
                    ":now, 100, :now)"
                ),
                {"now": _now().isoformat()},
            )

        base_time = datetime(2024, 6, 1, tzinfo=timezone.utc)

        for i in range(1, 4):
            result_id = f"res3-{i:02d}"
            gen_time = (base_time + timedelta(hours=i)).isoformat()
            expires_at = (base_time + timedelta(days=7, hours=i)).isoformat()

            with transaction(engine) as conn:
                conn.execute(
                    text(
                        "INSERT INTO ai_grading_result "
                        "(result_id, question_id, sheet_id, model, input_fingerprint, "
                        "dimension_scores_json, overall_score, comments_json, "
                        "highlights_json, issues_json, revised_version, "
                        "context_truncated, generated_at, expires_at) "
                        "VALUES (:result_id, 'q-02', 'sheet-ai2', 'deepseek-v4-flash', "
                        ":fingerprint, :dim_scores, 80.0, :comments, "
                        "'[]', '[]', 'Revised text.', "
                        "0, :gen_time, :expires_at)"
                    ),
                    {
                        "result_id": result_id,
                        "fingerprint": f"fp3-{i:02d}",
                        "dim_scores": '{"content":3,"structure":3,"language":3,"word_count":3}',
                        "comments": '{"content":"OK","structure":"OK","language":"OK","word_count":"OK"}',
                        "gen_time": gen_time,
                        "expires_at": expires_at,
                    },
                )

                conn.execute(
                    text(
                        "INSERT INTO ai_grading_history "
                        "(history_id, question_id, result_id, generated_at) "
                        "VALUES (:history_id, 'q-02', :result_id, :gen_time)"
                    ),
                    {
                        "history_id": f"hist3-{i:02d}",
                        "result_id": result_id,
                        "gen_time": gen_time,
                    },
                )

        # All 3 should remain
        with engine.connect() as conn:
            count = conn.execute(
                text(
                    "SELECT COUNT(*) FROM ai_grading_history "
                    "WHERE question_id = 'q-02'"
                )
            ).scalar()
            assert count == 3

    def test_different_questions_independent_limits(self, paper_repo: PaperRepo, engine: Engine):
        """History trimming is per-question — different questions have independent limits."""
        _setup_paper_with_questions(paper_repo, n_questions=5)

        with transaction(engine) as conn:
            conn.execute(
                text(
                    "INSERT INTO answer_sheet "
                    "(sheet_id, paper_id, status, mode, started_at, elapsed_seconds, updated_at) "
                    "VALUES ('sheet-ai3', '2024-12-set1', 'submitted', 'practice', "
                    ":now, 100, :now)"
                ),
                {"now": _now().isoformat()},
            )

        base_time = datetime(2024, 3, 1, tzinfo=timezone.utc)

        # Insert 6 entries for q-01 and 2 entries for q-02
        for i in range(1, 7):
            result_id = f"indep-q1-{i:02d}"
            gen_time = (base_time + timedelta(hours=i)).isoformat()
            expires_at = (base_time + timedelta(days=7, hours=i)).isoformat()

            with transaction(engine) as conn:
                conn.execute(
                    text(
                        "INSERT INTO ai_grading_result "
                        "(result_id, question_id, sheet_id, model, input_fingerprint, "
                        "dimension_scores_json, overall_score, comments_json, "
                        "highlights_json, issues_json, revised_version, "
                        "context_truncated, generated_at, expires_at) "
                        "VALUES (:result_id, 'q-01', 'sheet-ai3', 'deepseek-v4-flash', "
                        ":fingerprint, :dim_scores, 85.0, :comments, "
                        "'[]', '[]', 'Revised.', 0, :gen_time, :expires_at)"
                    ),
                    {
                        "result_id": result_id,
                        "fingerprint": f"indep-fp1-{i:02d}",
                        "dim_scores": '{"content":4,"structure":4,"language":4,"word_count":4}',
                        "comments": '{"content":"G","structure":"G","language":"G","word_count":"G"}',
                        "gen_time": gen_time,
                        "expires_at": expires_at,
                    },
                )
                conn.execute(
                    text(
                        "INSERT INTO ai_grading_history "
                        "(history_id, question_id, result_id, generated_at) "
                        "VALUES (:history_id, 'q-01', :result_id, :gen_time)"
                    ),
                    {
                        "history_id": f"indep-h1-{i:02d}",
                        "result_id": result_id,
                        "gen_time": gen_time,
                    },
                )

        for i in range(1, 3):
            result_id = f"indep-q2-{i:02d}"
            gen_time = (base_time + timedelta(hours=i)).isoformat()
            expires_at = (base_time + timedelta(days=7, hours=i)).isoformat()

            with transaction(engine) as conn:
                conn.execute(
                    text(
                        "INSERT INTO ai_grading_result "
                        "(result_id, question_id, sheet_id, model, input_fingerprint, "
                        "dimension_scores_json, overall_score, comments_json, "
                        "highlights_json, issues_json, revised_version, "
                        "context_truncated, generated_at, expires_at) "
                        "VALUES (:result_id, 'q-02', 'sheet-ai3', 'deepseek-v4-flash', "
                        ":fingerprint, :dim_scores, 80.0, :comments, "
                        "'[]', '[]', 'Revised.', 0, :gen_time, :expires_at)"
                    ),
                    {
                        "result_id": result_id,
                        "fingerprint": f"indep-fp2-{i:02d}",
                        "dim_scores": '{"content":3,"structure":3,"language":3,"word_count":3}',
                        "comments": '{"content":"O","structure":"O","language":"O","word_count":"O"}',
                        "gen_time": gen_time,
                        "expires_at": expires_at,
                    },
                )
                conn.execute(
                    text(
                        "INSERT INTO ai_grading_history "
                        "(history_id, question_id, result_id, generated_at) "
                        "VALUES (:history_id, 'q-02', :result_id, :gen_time)"
                    ),
                    {
                        "history_id": f"indep-h2-{i:02d}",
                        "result_id": result_id,
                        "gen_time": gen_time,
                    },
                )

        # q-01 should have 5 (trimmed from 6), q-02 should have 2 (untouched)
        with engine.connect() as conn:
            q1_count = conn.execute(
                text("SELECT COUNT(*) FROM ai_grading_history WHERE question_id = 'q-01'")
            ).scalar()
            q2_count = conn.execute(
                text("SELECT COUNT(*) FROM ai_grading_history WHERE question_id = 'q-02'")
            ).scalar()
            assert q1_count == 5
            assert q2_count == 2
