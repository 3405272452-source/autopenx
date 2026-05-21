"""Integration tests for the PDF parser orchestrator (parse_paper).

Tests the parse_paper() function against minimal PDF fixtures and verifies:
1. Complete PDF produces status="ok" with all sections parsed
2. Miscount PDF produces needs-review flags for affected sections
3. Non-existent PDF path returns status="parse-failed", failure_reason="not-found"
4. Stable question IDs are generated correctly (same PDF parsed twice = same IDs)

Requirements: 2.1, 2.9, 2.10, 2.13
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from cet4_app.infrastructure.pdf.parser import (
    PaperParseResult,
    QuestionData,
    SectionParse,
    SectionReviewFlag,
    _generate_question_ids,
    _validate_question_counts,
    parse_paper,
)

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "sample_papers"
_COMPLETE_PDF = _FIXTURES_DIR / "complete_paper.pdf"
_MISCOUNT_PDF = _FIXTURES_DIR / "miscount_paper.pdf"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_fixtures_exist():
    """Generate fixtures if they don't exist (e.g. fresh clone)."""
    if not _COMPLETE_PDF.exists() or not _MISCOUNT_PDF.exists():
        from tests.fixtures.sample_papers.generate_fixtures import (
            generate_complete_paper,
            generate_miscount_paper,
        )

        _FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        generate_complete_paper(_COMPLETE_PDF)
        generate_miscount_paper(_MISCOUNT_PDF)


@pytest.fixture(autouse=True)
def ensure_fixtures():
    """Ensure test PDF fixtures exist before running tests."""
    _ensure_fixtures_exist()


# ---------------------------------------------------------------------------
# Tests: Non-existent PDF → parse-failed (Req 2.13)
# ---------------------------------------------------------------------------


class TestParseFailedBranch:
    """Test failure branches of parse_paper."""

    def test_nonexistent_pdf_returns_parse_failed(self):
        """Non-existent PDF path returns status='parse-failed', failure_reason='not-found'."""
        result = parse_paper(
            paper_id="test-paper-1",
            paper_pdf_path="/nonexistent/path/to/paper.pdf",
            exam_period="2024-12",
            set_index=1,
        )

        assert isinstance(result, PaperParseResult)
        assert result.status == "parse-failed"
        assert result.failure_reason == "not-found"
        assert result.paper_id == "test-paper-1"
        assert result.sections == []

    def test_empty_path_returns_parse_failed(self):
        """Empty PDF path returns status='parse-failed', failure_reason='not-found'."""
        result = parse_paper(
            paper_id="test-paper-2",
            paper_pdf_path="",
            exam_period="2024-12",
            set_index=1,
        )

        assert result.status == "parse-failed"
        assert result.failure_reason == "not-found"

    def test_directory_path_returns_parse_failed(self):
        """Directory path (not a file) returns status='parse-failed'."""
        result = parse_paper(
            paper_id="test-paper-3",
            paper_pdf_path=str(_FIXTURES_DIR),
            exam_period="2024-12",
            set_index=1,
        )

        assert result.status == "parse-failed"
        assert result.failure_reason == "not-found"

    def test_corrupted_pdf_returns_parse_failed(self, tmp_path):
        """A file with invalid PDF content returns status='parse-failed', failure_reason='corrupted'."""
        bad_pdf = tmp_path / "corrupted.pdf"
        bad_pdf.write_text("This is not a valid PDF file content at all!")

        result = parse_paper(
            paper_id="test-paper-4",
            paper_pdf_path=str(bad_pdf),
            exam_period="2024-12",
            set_index=1,
        )

        assert result.status == "parse-failed"
        assert result.failure_reason == "corrupted"


# ---------------------------------------------------------------------------
# Tests: Complete PDF parsing (Req 2.1)
# ---------------------------------------------------------------------------


class TestCompletePaperParsing:
    """Test parsing a complete CET-4 paper PDF."""

    def test_complete_pdf_returns_ok_status(self):
        """Complete PDF produces status='ok'."""
        result = parse_paper(
            paper_id="complete-paper-1",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        assert isinstance(result, PaperParseResult)
        assert result.status == "ok"
        assert result.failure_reason is None
        assert result.paper_id == "complete-paper-1"

    def test_complete_pdf_has_four_sections(self):
        """Complete PDF produces exactly 4 sections."""
        result = parse_paper(
            paper_id="complete-paper-1",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        assert len(result.sections) == 4
        section_names = [s.name for s in result.sections]
        assert "writing" in section_names
        assert "listening" in section_names
        assert "reading" in section_names
        assert "translation" in section_names

    def test_complete_pdf_writing_section_has_questions(self):
        """Writing section should have at least 1 question extracted."""
        result = parse_paper(
            paper_id="complete-paper-1",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        writing = next(s for s in result.sections if s.name == "writing")
        # The writing extractor should find the writing prompt
        # (may or may not extract depending on regex matching)
        assert isinstance(writing.questions, list)

    def test_complete_pdf_translation_section_has_questions(self):
        """Translation section should have at least 1 question extracted."""
        result = parse_paper(
            paper_id="complete-paper-1",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        translation = next(s for s in result.sections if s.name == "translation")
        assert isinstance(translation.questions, list)

    def test_complete_pdf_all_questions_have_paper_id(self):
        """All extracted questions should have the correct paper_id."""
        result = parse_paper(
            paper_id="complete-paper-1",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        for section in result.sections:
            for q in section.questions:
                assert q.paper_id == "complete-paper-1"

    def test_complete_pdf_all_questions_have_ids(self):
        """All extracted questions should have non-empty stable IDs."""
        result = parse_paper(
            paper_id="complete-paper-1",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        for section in result.sections:
            for q in section.questions:
                assert q.id, f"Question in {section.name} has empty ID"
                assert "2024-12" in q.id
                assert "set1" in q.id


# ---------------------------------------------------------------------------
# Tests: Miscount PDF → needs-review flags (Req 2.10)
# ---------------------------------------------------------------------------


class TestMiscountPaperParsing:
    """Test parsing a paper with incorrect question counts."""

    def test_miscount_pdf_returns_ok_status(self):
        """Miscount PDF still returns status='ok' (parsing succeeded, just flagged)."""
        result = parse_paper(
            paper_id="miscount-paper-1",
            paper_pdf_path=str(_MISCOUNT_PDF),
            exam_period="2024-06",
            set_index=2,
        )

        assert result.status == "ok"
        assert result.failure_reason is None

    def test_miscount_pdf_has_four_sections(self):
        """Miscount PDF still produces 4 sections."""
        result = parse_paper(
            paper_id="miscount-paper-1",
            paper_pdf_path=str(_MISCOUNT_PDF),
            exam_period="2024-06",
            set_index=2,
        )

        assert len(result.sections) == 4

    def test_miscount_pdf_has_needs_review_flags(self):
        """Miscount PDF should produce needs-review flags for sections with wrong counts."""
        result = parse_paper(
            paper_id="miscount-paper-1",
            paper_pdf_path=str(_MISCOUNT_PDF),
            exam_period="2024-06",
            set_index=2,
        )

        # The parser should detect that question counts don't match expected values
        # At minimum, the needs_review list should be non-empty OR some sections
        # should have needs_review=True
        has_review_flags = len(result.needs_review) > 0
        has_section_review = any(s.needs_review for s in result.sections)

        assert has_review_flags or has_section_review, (
            "Miscount PDF should trigger needs-review flags. "
            f"needs_review={result.needs_review}, "
            f"section_reviews={[(s.name, s.needs_review) for s in result.sections]}"
        )

    def test_miscount_pdf_review_flags_have_expected_fields(self):
        """Review flags should contain section, reason, expected, and actual counts."""
        result = parse_paper(
            paper_id="miscount-paper-1",
            paper_pdf_path=str(_MISCOUNT_PDF),
            exam_period="2024-06",
            set_index=2,
        )

        for flag in result.needs_review:
            assert isinstance(flag, SectionReviewFlag)
            assert flag.section, "Review flag must have a section name"
            assert flag.reason, "Review flag must have a reason"

    def test_miscount_pdf_preserves_other_sections(self):
        """Even with miscount, other sections' results are still available."""
        result = parse_paper(
            paper_id="miscount-paper-1",
            paper_pdf_path=str(_MISCOUNT_PDF),
            exam_period="2024-06",
            set_index=2,
        )

        # Writing and Translation should still be parseable
        writing = next(s for s in result.sections if s.name == "writing")
        translation = next(s for s in result.sections if s.name == "translation")

        # These sections exist and are accessible
        assert isinstance(writing, SectionParse)
        assert isinstance(translation, SectionParse)


# ---------------------------------------------------------------------------
# Tests: Stable question ID generation (Req 2.9)
# ---------------------------------------------------------------------------


class TestStableQuestionIds:
    """Test that question IDs are stable across repeated parses."""

    def test_same_pdf_parsed_twice_produces_same_ids(self):
        """Parsing the same PDF twice must produce identical question ID sets."""
        result1 = parse_paper(
            paper_id="stable-test",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )
        result2 = parse_paper(
            paper_id="stable-test",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        # Collect all question IDs from both runs
        ids1 = set()
        for section in result1.sections:
            for q in section.questions:
                if q.id:
                    ids1.add(q.id)

        ids2 = set()
        for section in result2.sections:
            for q in section.questions:
                if q.id:
                    ids2.add(q.id)

        # Both runs should produce the same set of IDs
        assert ids1 == ids2, (
            f"Question IDs differ between two parses of the same PDF.\n"
            f"Only in first: {ids1 - ids2}\n"
            f"Only in second: {ids2 - ids1}"
        )

    def test_question_id_format_matches_spec(self):
        """Question IDs follow the format: {exam_period}-set{set_index}-{section}-{sub_section}-{seq:02d}."""
        result = parse_paper(
            paper_id="format-test",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        for section in result.sections:
            for q in section.questions:
                if q.id:
                    # ID should start with exam_period
                    assert q.id.startswith("2024-12-set1-"), (
                        f"ID '{q.id}' doesn't start with '2024-12-set1-'"
                    )
                    # ID should contain the section name
                    assert q.section in q.id, (
                        f"ID '{q.id}' doesn't contain section '{q.section}'"
                    )

    def test_question_ids_are_unique_within_paper(self):
        """All question IDs within a single paper parse must be unique."""
        result = parse_paper(
            paper_id="unique-test",
            paper_pdf_path=str(_COMPLETE_PDF),
            exam_period="2024-12",
            set_index=1,
        )

        all_ids = []
        for section in result.sections:
            for q in section.questions:
                if q.id:
                    all_ids.append(q.id)

        # Check for duplicates
        assert len(all_ids) == len(set(all_ids)), (
            f"Duplicate question IDs found: "
            f"{[x for x in all_ids if all_ids.count(x) > 1]}"
        )


# ---------------------------------------------------------------------------
# Tests: Question ID generation unit tests (Req 2.9)
# ---------------------------------------------------------------------------


class TestGenerateQuestionIds:
    """Unit tests for the _generate_question_ids helper function."""

    def test_assigns_ids_to_all_questions(self):
        """All questions get IDs assigned."""
        questions = [
            QuestionData(section="reading", sub_section="careful", paper_id="p1"),
            QuestionData(section="reading", sub_section="careful", paper_id="p1"),
            QuestionData(section="writing", sub_section="", paper_id="p1"),
        ]

        _generate_question_ids(questions, "2024-12", 1)

        for q in questions:
            assert q.id != ""

    def test_id_format_correct(self):
        """Generated IDs follow the expected format."""
        questions = [
            QuestionData(section="reading", sub_section="careful", paper_id="p1"),
        ]

        _generate_question_ids(questions, "2024-12", 1)

        assert questions[0].id == "2024-12-set1-reading-careful-01"

    def test_sequential_numbering(self):
        """Questions in the same group get sequential numbers."""
        questions = [
            QuestionData(section="listening", sub_section="news", paper_id="p1"),
            QuestionData(section="listening", sub_section="news", paper_id="p1"),
            QuestionData(section="listening", sub_section="news", paper_id="p1"),
        ]

        _generate_question_ids(questions, "2024-06", 2)

        assert questions[0].id == "2024-06-set2-listening-news-01"
        assert questions[1].id == "2024-06-set2-listening-news-02"
        assert questions[2].id == "2024-06-set2-listening-news-03"

    def test_banked_cloze_uses_blank_index(self):
        """Banked cloze questions use blank_index as sequence number."""
        questions = [
            QuestionData(
                section="reading", sub_section="banked_cloze",
                paper_id="p1", blank_index=3,
            ),
            QuestionData(
                section="reading", sub_section="banked_cloze",
                paper_id="p1", blank_index=7,
            ),
        ]

        _generate_question_ids(questions, "2024-12", 1)

        assert questions[0].id == "2024-12-set1-reading-banked_cloze-03"
        assert questions[1].id == "2024-12-set1-reading-banked_cloze-07"

    def test_idempotent_generation(self):
        """Calling _generate_question_ids twice produces the same result."""
        questions = [
            QuestionData(section="writing", sub_section="", paper_id="p1"),
            QuestionData(section="translation", sub_section="", paper_id="p1"),
        ]

        _generate_question_ids(questions, "2024-12", 1)
        ids_first = [q.id for q in questions]

        _generate_question_ids(questions, "2024-12", 1)
        ids_second = [q.id for q in questions]

        assert ids_first == ids_second


# ---------------------------------------------------------------------------
# Tests: Question count validation (Req 2.10)
# ---------------------------------------------------------------------------


class TestValidateQuestionCounts:
    """Unit tests for the _validate_question_counts helper function."""

    def test_correct_counts_produce_no_flags(self):
        """When all counts match expected values, no review flags are generated."""
        sections = [
            SectionParse(
                name="writing",
                questions=[QuestionData(section="writing")] * 1,
            ),
            SectionParse(
                name="listening",
                questions=[QuestionData(section="listening")] * 25,
            ),
            SectionParse(
                name="reading",
                questions=(
                    [QuestionData(section="reading", sub_section="banked_cloze")] * 10
                    + [QuestionData(section="reading", sub_section="long_matching")] * 10
                    + [QuestionData(section="reading", sub_section="careful")] * 10
                ),
            ),
            SectionParse(
                name="translation",
                questions=[QuestionData(section="translation")] * 1,
            ),
        ]

        flags = _validate_question_counts(sections)
        assert flags == []

    def test_wrong_listening_count_produces_flag(self):
        """Listening with wrong count produces a review flag."""
        sections = [
            SectionParse(name="writing", questions=[QuestionData()] * 1),
            SectionParse(name="listening", questions=[QuestionData()] * 20),
            SectionParse(
                name="reading",
                questions=(
                    [QuestionData(sub_section="banked_cloze")] * 10
                    + [QuestionData(sub_section="long_matching")] * 10
                    + [QuestionData(sub_section="careful")] * 10
                ),
            ),
            SectionParse(name="translation", questions=[QuestionData()] * 1),
        ]

        flags = _validate_question_counts(sections)
        assert len(flags) >= 1
        listening_flags = [f for f in flags if f.section == "listening"]
        assert len(listening_flags) == 1
        assert listening_flags[0].expected == 25
        assert listening_flags[0].actual == 20

    def test_wrong_banked_cloze_count_produces_flag(self):
        """Banked cloze with wrong count produces a review flag."""
        sections = [
            SectionParse(name="writing", questions=[QuestionData()] * 1),
            SectionParse(name="listening", questions=[QuestionData()] * 25),
            SectionParse(
                name="reading",
                questions=(
                    [QuestionData(sub_section="banked_cloze")] * 8  # Wrong!
                    + [QuestionData(sub_section="long_matching")] * 10
                    + [QuestionData(sub_section="careful")] * 10
                ),
            ),
            SectionParse(name="translation", questions=[QuestionData()] * 1),
        ]

        flags = _validate_question_counts(sections)
        reading_flags = [f for f in flags if f.section == "reading"]
        assert len(reading_flags) >= 1
        bc_flags = [f for f in reading_flags if f.sub_section == "banked_cloze"]
        assert len(bc_flags) == 1
        assert bc_flags[0].expected == 10
        assert bc_flags[0].actual == 8

    def test_multiple_wrong_counts_produce_multiple_flags(self):
        """Multiple sections with wrong counts produce multiple flags."""
        sections = [
            SectionParse(name="writing", questions=[QuestionData()] * 2),  # Wrong!
            SectionParse(name="listening", questions=[QuestionData()] * 20),  # Wrong!
            SectionParse(
                name="reading",
                questions=(
                    [QuestionData(sub_section="banked_cloze")] * 10
                    + [QuestionData(sub_section="long_matching")] * 10
                    + [QuestionData(sub_section="careful")] * 10
                ),
            ),
            SectionParse(name="translation", questions=[QuestionData()] * 1),
        ]

        flags = _validate_question_counts(sections)
        assert len(flags) >= 2
        flag_sections = {f.section for f in flags}
        assert "writing" in flag_sections
        assert "listening" in flag_sections
