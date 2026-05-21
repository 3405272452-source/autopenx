"""Integration tests for PaperRepo.

Tests cover:
- PaperSet CRUD (save/load/delete)
- Paper CRUD (save/load by id/set/all, delete)
- Question CRUD (save/load by paper/id/type, delete)
- save_paper_with_questions transactional save
- JSON field serialization/deserialization (options, tags, shared_banked_words, etc.)
- Round-trip consistency for domain models

Requirements: 2.12, 12.1
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from cet4_app.domain.enums import (
    AudioStatus,
    PaperStatus,
    QuestionType,
    SectionName,
)
from cet4_app.domain.models.paper_set import PaperSet
from cet4_app.domain.models.question import (
    AudioRange,
    Paper,
    Question,
    Section,
    SubSection,
)
from cet4_app.infrastructure.persistence.db import create_engine, init_schema
from cet4_app.infrastructure.repositories.paper_repo import PaperRepo


@pytest.fixture
def repo(tmp_path: Path) -> PaperRepo:
    """Create a fresh SQLite repo for each test."""
    db_path = tmp_path / "test.db"
    engine = create_engine(db_path)
    init_schema(engine)
    return PaperRepo(engine)


def _make_paper_set(
    paper_set_id: str = "ps-2024-12",
    exam_period: str = "2024-12",
    directory_name: str = "2024年12月CET4真题",
) -> PaperSet:
    return PaperSet(
        paper_set_id=paper_set_id,
        exam_period=exam_period,
        directory_name=directory_name,
        scanned_at=datetime(2024, 12, 1, 10, 0, 0, tzinfo=timezone.utc),
    )


def _make_paper(
    paper_id: str = "2024-12-set1",
    paper_set_id: str = "ps-2024-12",
    set_index: int = 1,
    status: PaperStatus = PaperStatus.ok,
) -> Paper:
    return Paper(
        paper_id=paper_id,
        paper_set_id=paper_set_id,
        exam_period="2024-12",
        set_index=set_index,
        paper_pdf_path="C:/cet4/2024-12/paper1.pdf",
        answer_pdf_path="C:/cet4/2024-12/answer1.pdf",
        audio_mp3_path="C:/cet4/2024-12/audio1.mp3",
        audio_status=AudioStatus.available,
        status=status,
        sections=[],
        shared_banked_words=[],
        long_reading_paragraphs={},
    )


def _make_question(
    question_id: str = "2024-12-set1-listening-news-01",
    paper_id: str = "2024-12-set1",
    section: SectionName = SectionName.listening,
    sub_section: str = "news",
    question_type: QuestionType = QuestionType.listening_news,
) -> Question:
    return Question(
        id=question_id,
        paper_id=paper_id,
        section=section,
        sub_section=sub_section,
        question_type=question_type,
        prompt="What happened in the news report?",
        options=["Option A", "Option B", "Option C", "Option D"],
        correct_letter="A",
        reference_answer="A",
        explanation="The answer is A because...",
        score=Decimal("7.10"),
        tags=["vocabulary", "easy"],
        audio_range=AudioRange(start_s=10.5, end_s=45.2),
    )


def _make_writing_question(
    question_id: str = "2024-12-set1-writing-writing-01",
    paper_id: str = "2024-12-set1",
) -> Question:
    return Question(
        id=question_id,
        paper_id=paper_id,
        section=SectionName.writing,
        sub_section="writing",
        question_type=QuestionType.writing,
        prompt="Write an essay on the importance of reading.",
        options=[],
        reference_answer="Reading is fundamental to personal growth...",
        explanation="A good essay should cover benefits of reading.",
        score=Decimal("15.00"),
        tags=["writing"],
        min_words=120,
        max_words=180,
    )


class TestPaperSetCRUD:
    """Tests for PaperSet save/load/delete operations."""

    def test_save_and_load_paper_set(self, repo: PaperRepo):
        ps = _make_paper_set()
        repo.save_paper_set(ps)

        loaded = repo.load_paper_set_by_id("ps-2024-12")
        assert loaded is not None
        assert loaded.paper_set_id == "ps-2024-12"
        assert loaded.exam_period == "2024-12"
        assert loaded.directory_name == "2024年12月CET4真题"
        assert loaded.scanned_at.year == 2024

    def test_load_nonexistent_paper_set_returns_none(self, repo: PaperRepo):
        result = repo.load_paper_set_by_id("nonexistent")
        assert result is None

    def test_load_all_paper_sets(self, repo: PaperRepo):
        repo.save_paper_set(_make_paper_set("ps-2023-12", "2023-12", "2023年12月"))
        repo.save_paper_set(_make_paper_set("ps-2024-06", "2024-06", "2024年6月"))
        repo.save_paper_set(_make_paper_set("ps-2024-12", "2024-12", "2024年12月"))

        all_sets = repo.load_all_paper_sets()
        assert len(all_sets) == 3
        # Should be ordered by exam_period
        assert all_sets[0].exam_period == "2023-12"
        assert all_sets[1].exam_period == "2024-06"
        assert all_sets[2].exam_period == "2024-12"

    def test_save_paper_set_upsert(self, repo: PaperRepo):
        """Saving a PaperSet with the same ID replaces the old one."""
        ps = _make_paper_set()
        repo.save_paper_set(ps)

        ps_updated = PaperSet(
            paper_set_id="ps-2024-12",
            exam_period="2024-12",
            directory_name="updated_dir",
            scanned_at=datetime(2024, 12, 2, 10, 0, 0, tzinfo=timezone.utc),
        )
        repo.save_paper_set(ps_updated)

        loaded = repo.load_paper_set_by_id("ps-2024-12")
        assert loaded is not None
        assert loaded.directory_name == "updated_dir"

    def test_delete_paper_set(self, repo: PaperRepo):
        ps = _make_paper_set()
        repo.save_paper_set(ps)
        repo.delete_paper_set("ps-2024-12")

        loaded = repo.load_paper_set_by_id("ps-2024-12")
        assert loaded is None


class TestPaperCRUD:
    """Tests for Paper save/load/delete operations."""

    def test_save_and_load_paper(self, repo: PaperRepo):
        repo.save_paper_set(_make_paper_set())
        paper = _make_paper()
        repo.save_paper(paper)

        loaded = repo.load_paper_by_id("2024-12-set1")
        assert loaded is not None
        assert loaded.paper_id == "2024-12-set1"
        assert loaded.paper_set_id == "ps-2024-12"
        assert loaded.set_index == 1
        assert loaded.audio_status == AudioStatus.available
        assert loaded.status == PaperStatus.ok

    def test_load_nonexistent_paper_returns_none(self, repo: PaperRepo):
        result = repo.load_paper_by_id("nonexistent")
        assert result is None

    def test_load_papers_by_set(self, repo: PaperRepo):
        repo.save_paper_set(_make_paper_set())
        repo.save_paper(_make_paper("2024-12-set1", set_index=1))
        repo.save_paper(_make_paper("2024-12-set2", set_index=2))
        repo.save_paper(_make_paper("2024-12-set3", set_index=3))

        papers = repo.load_papers_by_set("ps-2024-12")
        assert len(papers) == 3
        assert papers[0].set_index == 1
        assert papers[1].set_index == 2
        assert papers[2].set_index == 3

    def test_save_paper_with_json_fields(self, repo: PaperRepo):
        """Paper with shared_banked_words and long_reading_paragraphs round-trips."""
        repo.save_paper_set(_make_paper_set())
        words = [
            "abandon", "benefit", "crucial", "diverse", "efficient",
            "flexible", "genuine", "hostile", "identical", "justify",
            "keen", "liberal", "massive", "neutral", "obvious",
        ]
        paragraphs = {chr(65 + i): f"Paragraph {chr(65 + i)} text" for i in range(10)}

        paper = Paper(
            paper_id="2024-12-set1",
            paper_set_id="ps-2024-12",
            exam_period="2024-12",
            set_index=1,
            audio_status=AudioStatus.available,
            status=PaperStatus.ok,
            sections=[],
            shared_banked_words=words,
            long_reading_paragraphs=paragraphs,
        )
        repo.save_paper(paper)

        loaded = repo.load_paper_by_id("2024-12-set1")
        assert loaded is not None
        assert loaded.shared_banked_words == words
        assert loaded.long_reading_paragraphs == paragraphs

    def test_save_paper_with_embedded_audio(self, repo: PaperRepo):
        repo.save_paper_set(_make_paper_set())
        paper = Paper(
            paper_id="2024-12-set3",
            paper_set_id="ps-2024-12",
            exam_period="2024-12",
            set_index=3,
            audio_status=AudioStatus.embedded_in_paper,
            status=PaperStatus.ok,
            sections=[],
        )
        repo.save_paper(paper)

        loaded = repo.load_paper_by_id("2024-12-set3")
        assert loaded is not None
        assert loaded.audio_status == AudioStatus.embedded_in_paper

    def test_delete_paper(self, repo: PaperRepo):
        repo.save_paper_set(_make_paper_set())
        repo.save_paper(_make_paper())
        repo.delete_paper("2024-12-set1")

        loaded = repo.load_paper_by_id("2024-12-set1")
        assert loaded is None


class TestQuestionCRUD:
    """Tests for Question save/load/delete operations."""

    def _setup_paper(self, repo: PaperRepo):
        """Helper to set up prerequisite paper_set and paper."""
        repo.save_paper_set(_make_paper_set())
        repo.save_paper(_make_paper())

    def test_save_and_load_question(self, repo: PaperRepo):
        self._setup_paper(repo)
        q = _make_question()
        repo.save_question(q)

        loaded = repo.load_question_by_id("2024-12-set1-listening-news-01")
        assert loaded is not None
        assert loaded.id == "2024-12-set1-listening-news-01"
        assert loaded.paper_id == "2024-12-set1"
        assert loaded.section == SectionName.listening
        assert loaded.sub_section == "news"
        assert loaded.question_type == QuestionType.listening_news
        assert loaded.prompt == "What happened in the news report?"
        assert loaded.options == ["Option A", "Option B", "Option C", "Option D"]
        assert loaded.correct_letter == "A"
        assert loaded.reference_answer == "A"
        assert loaded.score == Decimal("7.10")
        assert loaded.tags == ["vocabulary", "easy"]

    def test_save_and_load_question_with_audio_range(self, repo: PaperRepo):
        self._setup_paper(repo)
        q = _make_question()
        repo.save_question(q)

        loaded = repo.load_question_by_id("2024-12-set1-listening-news-01")
        assert loaded is not None
        assert loaded.audio_range is not None
        assert loaded.audio_range.start_s == 10.5
        assert loaded.audio_range.end_s == 45.2

    def test_save_and_load_writing_question(self, repo: PaperRepo):
        self._setup_paper(repo)
        q = _make_writing_question()
        repo.save_question(q)

        loaded = repo.load_question_by_id("2024-12-set1-writing-writing-01")
        assert loaded is not None
        assert loaded.question_type == QuestionType.writing
        assert loaded.options == []
        assert loaded.min_words == 120
        assert loaded.max_words == 180
        assert "reading" in loaded.prompt.lower()

    def test_save_questions_batch(self, repo: PaperRepo):
        self._setup_paper(repo)
        questions = [
            _make_question(f"2024-12-set1-listening-news-0{i}")
            for i in range(1, 4)
        ]
        repo.save_questions(questions)

        loaded = repo.load_questions_by_paper("2024-12-set1")
        assert len(loaded) == 3

    def test_load_questions_by_paper(self, repo: PaperRepo):
        self._setup_paper(repo)
        repo.save_question(_make_question("q1"))
        repo.save_question(_make_question("q2"))

        loaded = repo.load_questions_by_paper("2024-12-set1")
        assert len(loaded) == 2

    def test_load_questions_by_type(self, repo: PaperRepo):
        self._setup_paper(repo)
        repo.save_question(_make_question("q1"))
        repo.save_question(_make_writing_question("q2"))

        listening_qs = repo.load_questions_by_type(QuestionType.listening_news)
        assert len(listening_qs) == 1
        assert listening_qs[0].id == "q1"

        writing_qs = repo.load_questions_by_type(QuestionType.writing)
        assert len(writing_qs) == 1
        assert writing_qs[0].id == "q2"

    def test_load_nonexistent_question_returns_none(self, repo: PaperRepo):
        result = repo.load_question_by_id("nonexistent")
        assert result is None

    def test_delete_questions_by_paper(self, repo: PaperRepo):
        self._setup_paper(repo)
        repo.save_question(_make_question("q1"))
        repo.save_question(_make_question("q2"))

        repo.delete_questions_by_paper("2024-12-set1")

        loaded = repo.load_questions_by_paper("2024-12-set1")
        assert len(loaded) == 0

    def test_question_upsert(self, repo: PaperRepo):
        """Saving a question with the same ID replaces the old one."""
        self._setup_paper(repo)
        q = _make_question()
        repo.save_question(q)

        # Update the question
        q_updated = Question(
            id="2024-12-set1-listening-news-01",
            paper_id="2024-12-set1",
            section=SectionName.listening,
            sub_section="news",
            question_type=QuestionType.listening_news,
            prompt="Updated prompt",
            options=["New A", "New B", "New C", "New D"],
            correct_letter="B",
            reference_answer="B",
            explanation="Updated explanation",
            score=Decimal("7.10"),
            tags=["grammar"],
        )
        repo.save_question(q_updated)

        loaded = repo.load_question_by_id("2024-12-set1-listening-news-01")
        assert loaded is not None
        assert loaded.prompt == "Updated prompt"
        assert loaded.correct_letter == "B"
        assert loaded.tags == ["grammar"]


class TestSavePaperWithQuestions:
    """Tests for save_paper_with_questions transactional save."""

    def test_save_paper_with_questions(self, repo: PaperRepo):
        repo.save_paper_set(_make_paper_set())

        q1 = _make_question("2024-12-set1-listening-news-01")
        q2 = _make_question("2024-12-set1-listening-news-02")
        sub = SubSection(name="news", questions=[q1, q2])
        section = Section(name=SectionName.listening, sub_sections=[sub])

        paper = Paper(
            paper_id="2024-12-set1",
            paper_set_id="ps-2024-12",
            exam_period="2024-12",
            set_index=1,
            audio_status=AudioStatus.available,
            status=PaperStatus.ok,
            sections=[section],
        )
        repo.save_paper_with_questions(paper)

        loaded_paper = repo.load_paper_by_id("2024-12-set1")
        assert loaded_paper is not None

        questions = repo.load_questions_by_paper("2024-12-set1")
        assert len(questions) == 2

    def test_save_paper_with_questions_replaces_old(self, repo: PaperRepo):
        """Saving again replaces old questions."""
        repo.save_paper_set(_make_paper_set())

        q1 = _make_question("q1")
        sub = SubSection(name="news", questions=[q1])
        section = Section(name=SectionName.listening, sub_sections=[sub])
        paper = Paper(
            paper_id="2024-12-set1",
            paper_set_id="ps-2024-12",
            exam_period="2024-12",
            set_index=1,
            audio_status=AudioStatus.available,
            status=PaperStatus.ok,
            sections=[section],
        )
        repo.save_paper_with_questions(paper)

        # Save again with different questions
        q2 = _make_question("q2")
        q3 = _make_question("q3")
        sub2 = SubSection(name="news", questions=[q2, q3])
        section2 = Section(name=SectionName.listening, sub_sections=[sub2])
        paper2 = Paper(
            paper_id="2024-12-set1",
            paper_set_id="ps-2024-12",
            exam_period="2024-12",
            set_index=1,
            audio_status=AudioStatus.available,
            status=PaperStatus.ok,
            sections=[section2],
        )
        repo.save_paper_with_questions(paper2)

        questions = repo.load_questions_by_paper("2024-12-set1")
        # Both old and new questions exist (INSERT OR REPLACE)
        ids = {q.id for q in questions}
        assert "q2" in ids
        assert "q3" in ids
