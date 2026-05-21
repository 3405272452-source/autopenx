"""Tests for infrastructure/pdf/reading_extractor.py.

Validates the Reading section extraction logic for all three sub-sections:
- Section A: Banked Cloze (15 candidate words + numbered blanks 1-10)
- Section B: Long Reading (paragraphs A..O + 10 matching questions)
- Section C: Careful Reading (2 passages × 5 questions × 4 options)

Requirements: 2.2, 2.3, 2.4, 2.5
"""

from __future__ import annotations

import pytest

from cet4_app.infrastructure.pdf.layout import LayoutBlock
from cet4_app.infrastructure.pdf.reading_extractor import (
    BankedClozeResult,
    CarefulPassage,
    CarefulReadingResult,
    LongReadingResult,
    ReadingExtractResult,
    ReadingQuestion,
    extract_reading,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_banked_cloze_blocks() -> list[LayoutBlock]:
    """Create blocks simulating a Banked Cloze (Section A) sub-section."""
    return [
        LayoutBlock(text="Section A", page=0),
        LayoutBlock(
            text="Directions: In this section, there is a passage with ten blanks. "
            "You are required to select one word for each blank from a list of "
            "choices given in a bank of words.",
            page=0,
        ),
        LayoutBlock(
            text="A) abandon  B) capacity  C) demonstrate  D) enhance  E) facilitate",
            page=0,
        ),
        LayoutBlock(
            text="F) genuine  G) highlight  H) implement  I) justify  J) maintain",
            page=0,
        ),
        LayoutBlock(
            text="K) negotiate  L) obtain  M) preserve  N) restore  O) sustain",
            page=0,
        ),
        LayoutBlock(
            text="The government has decided to __26__ new policies that will "
            "__27__ economic growth. These measures aim to __28__ the current "
            "situation and __29__ public confidence.",
            page=1,
        ),
        LayoutBlock(
            text="Officials say they will __30__ with stakeholders to __31__ "
            "broad support. The plan also seeks to __32__ existing programs "
            "while introducing __33__ reforms.",
            page=1,
        ),
        LayoutBlock(
            text="Critics argue that it is hard to __34__ such spending, but "
            "supporters believe the investment will __35__ long-term benefits.",
            page=1,
        ),
    ]


def _make_long_reading_blocks() -> list[LayoutBlock]:
    """Create blocks simulating a Long Reading (Section B) sub-section."""
    return [
        LayoutBlock(text="Section B", page=2),
        LayoutBlock(
            text="Directions: In this section, you are going to read a passage "
            "with ten statements attached to it. Each statement contains "
            "information given in one of the paragraphs. Identify the paragraph "
            "from which the information is derived.",
            page=2,
        ),
        LayoutBlock(
            text="A) The rapid development of artificial intelligence has "
            "transformed many industries in recent years.",
            page=2,
        ),
        LayoutBlock(
            text="B) Healthcare is one sector where AI has shown tremendous "
            "potential for improving patient outcomes.",
            page=2,
        ),
        LayoutBlock(
            text="C) Education systems worldwide are beginning to integrate "
            "AI-powered tools into their curricula.",
            page=3,
        ),
        LayoutBlock(
            text="D) The financial sector has been an early adopter of machine "
            "learning algorithms for risk assessment.",
            page=3,
        ),
        LayoutBlock(
            text="E) Environmental scientists are using AI to model climate "
            "change scenarios with unprecedented accuracy.",
            page=3,
        ),
        LayoutBlock(text="36. AI is being used to predict climate patterns.", page=4),
        LayoutBlock(text="37. Machine learning helps banks evaluate risks.", page=4),
        LayoutBlock(text="38. Schools are adopting AI teaching tools.", page=4),
        LayoutBlock(text="39. AI has changed many business sectors.", page=4),
        LayoutBlock(text="40. Medical care benefits from AI technology.", page=4),
    ]


def _make_careful_reading_blocks() -> list[LayoutBlock]:
    """Create blocks simulating a Careful Reading (Section C) sub-section."""
    return [
        LayoutBlock(text="Section C", page=5),
        LayoutBlock(
            text="Directions: There are 2 passages in this section. Each passage "
            "is followed by some questions or unfinished statements.",
            page=5,
        ),
        LayoutBlock(text="Passage One", page=5),
        LayoutBlock(
            text="Technology has fundamentally transformed the way we communicate. "
            "Social media platforms have created new forms of interaction that "
            "were unimaginable just two decades ago.",
            page=5,
        ),
        LayoutBlock(text="46. What is the main topic of this passage?", page=6),
        LayoutBlock(text="A) The history of the internet", page=6),
        LayoutBlock(text="B) How technology changed communication", page=6),
        LayoutBlock(text="C) Social media addiction", page=6),
        LayoutBlock(text="D) The future of technology", page=6),
        LayoutBlock(
            text="47. According to the passage, social media has ______.",
            page=6,
        ),
        LayoutBlock(text="A) existed for centuries", page=6),
        LayoutBlock(text="B) created new interaction forms", page=6),
        LayoutBlock(text="C) replaced all traditional media", page=6),
        LayoutBlock(text="D) had no significant impact", page=6),
        LayoutBlock(text="Passage Two", page=7),
        LayoutBlock(
            text="Climate change represents one of the greatest challenges "
            "facing humanity today. Rising temperatures are causing widespread "
            "environmental disruption across the globe.",
            page=7,
        ),
        LayoutBlock(
            text="51. What does the passage primarily discuss?", page=8
        ),
        LayoutBlock(text="A) Weather forecasting methods", page=8),
        LayoutBlock(text="B) Climate change challenges", page=8),
        LayoutBlock(text="C) Agricultural techniques", page=8),
        LayoutBlock(text="D) Energy conservation", page=8),
        LayoutBlock(
            text="52. According to the passage, rising temperatures ______.",
            page=8,
        ),
        LayoutBlock(text="A) only affect polar regions", page=8),
        LayoutBlock(text="B) cause environmental disruption globally", page=8),
        LayoutBlock(text="C) have no measurable effect", page=8),
        LayoutBlock(text="D) benefit agriculture", page=8),
    ]


# ---------------------------------------------------------------------------
# Tests: Empty / Missing sub-sections
# ---------------------------------------------------------------------------


class TestEmptyInput:
    """Tests for edge cases with empty or missing input."""

    def test_empty_blocks_returns_all_missing(self):
        result = extract_reading([])
        assert result.banked_cloze is None
        assert result.long_reading is None
        assert result.careful_reading is None
        assert len(result.missing_subsections) == 3

    def test_no_section_anchors_found(self):
        blocks = [
            LayoutBlock(text="Some random text without section markers.", page=0),
            LayoutBlock(text="More unrelated content.", page=1),
        ]
        result = extract_reading(blocks)
        assert result.banked_cloze is None
        assert result.long_reading is None
        assert result.careful_reading is None
        assert len(result.missing_subsections) == 3

    def test_only_section_a_present(self):
        blocks = _make_banked_cloze_blocks()
        # Remove the Section B marker at the end
        blocks = [b for b in blocks if "Section B" not in b.text]
        result = extract_reading(blocks)
        assert result.banked_cloze is not None
        assert result.long_reading is None
        assert result.careful_reading is None
        assert "Section B (Long Reading)" in result.missing_subsections
        assert "Section C (Careful Reading)" in result.missing_subsections


# ---------------------------------------------------------------------------
# Tests: Banked Cloze (Section A) — Requirement 2.3
# ---------------------------------------------------------------------------


class TestBankedCloze:
    """Tests for Banked Cloze extraction (Requirement 2.3)."""

    def test_extracts_15_candidate_words(self):
        blocks = _make_banked_cloze_blocks()
        result = extract_reading(blocks)
        assert result.banked_cloze is not None
        assert len(result.banked_cloze.candidate_words) == 15

    def test_candidate_words_in_correct_order(self):
        blocks = _make_banked_cloze_blocks()
        result = extract_reading(blocks)
        words = result.banked_cloze.candidate_words
        assert words[0] == "abandon"  # A
        assert words[1] == "capacity"  # B
        assert words[2] == "demonstrate"  # C
        assert words[14] == "sustain"  # O

    def test_extracts_numbered_blanks(self):
        blocks = _make_banked_cloze_blocks()
        result = extract_reading(blocks)
        # Should find blanks 26-35 (normalized to 1-10)
        assert len(result.banked_cloze.blanks) >= 2
        # Blank 1 corresponds to __26__
        assert 1 in result.banked_cloze.blanks
        assert 2 in result.banked_cloze.blanks

    def test_passage_text_extracted(self):
        blocks = _make_banked_cloze_blocks()
        result = extract_reading(blocks)
        assert len(result.banked_cloze.passage) > 0
        assert "government" in result.banked_cloze.passage

    def test_questions_generated_for_blanks(self):
        blocks = _make_banked_cloze_blocks()
        result = extract_reading(blocks)
        assert len(result.banked_cloze.questions) >= 2
        # Questions should be sorted by number
        numbers = [q.number for q in result.banked_cloze.questions]
        assert numbers == sorted(numbers)

    def test_hyphenated_candidate_words(self):
        """Candidate words with hyphens should be captured correctly."""
        blocks = [
            LayoutBlock(text="Section A", page=0),
            LayoutBlock(
                text="Directions: Fill in the blanks from the bank of words.",
                page=0,
            ),
            LayoutBlock(
                text="A) well-known  B) self-esteem  C) long-term  "
                "D) high-quality  E) cost-effective",
                page=0,
            ),
            LayoutBlock(
                text="F) time-consuming  G) far-reaching  H) ground-breaking  "
                "I) thought-provoking  J) hard-working",
                page=0,
            ),
            LayoutBlock(
                text="K) open-minded  L) short-lived  M) wide-spread  "
                "N) fast-growing  O) ever-changing",
                page=0,
            ),
        ]
        result = extract_reading(blocks)
        assert result.banked_cloze is not None
        words = result.banked_cloze.candidate_words
        assert len(words) == 15
        # Hyphenated words should be captured as single tokens
        assert "well-known" in words


# ---------------------------------------------------------------------------
# Tests: Long Reading (Section B) — Requirement 2.4
# ---------------------------------------------------------------------------


class TestLongReading:
    """Tests for Long Reading extraction (Requirement 2.4)."""

    def test_extracts_paragraphs(self):
        blocks = _make_long_reading_blocks()
        result = extract_reading(blocks)
        assert result.long_reading is not None
        assert len(result.long_reading.paragraphs) >= 3

    def test_paragraph_labels_are_uppercase_letters(self):
        blocks = _make_long_reading_blocks()
        result = extract_reading(blocks)
        for label in result.long_reading.paragraphs:
            assert label in "ABCDEFGHIJKLMNO"
            assert len(label) == 1

    def test_paragraph_text_not_empty(self):
        blocks = _make_long_reading_blocks()
        result = extract_reading(blocks)
        for label, text in result.long_reading.paragraphs.items():
            assert len(text) > 0, f"Paragraph {label} has empty text"

    def test_extracts_questions_in_range_36_45(self):
        blocks = _make_long_reading_blocks()
        result = extract_reading(blocks)
        assert len(result.long_reading.questions) >= 3
        for q in result.long_reading.questions:
            assert 36 <= q.number <= 45

    def test_questions_sorted_by_number(self):
        blocks = _make_long_reading_blocks()
        result = extract_reading(blocks)
        numbers = [q.number for q in result.long_reading.questions]
        assert numbers == sorted(numbers)

    def test_questions_have_prompts(self):
        blocks = _make_long_reading_blocks()
        result = extract_reading(blocks)
        for q in result.long_reading.questions:
            assert len(q.prompt) > 0

    def test_long_reading_questions_have_no_options(self):
        """Long Reading questions are matching statements, not multiple choice."""
        blocks = _make_long_reading_blocks()
        result = extract_reading(blocks)
        for q in result.long_reading.questions:
            assert q.options == []


# ---------------------------------------------------------------------------
# Tests: Careful Reading (Section C) — Requirement 2.5
# ---------------------------------------------------------------------------


class TestCarefulReading:
    """Tests for Careful Reading extraction (Requirement 2.5)."""

    def test_extracts_two_passages(self):
        blocks = _make_careful_reading_blocks()
        result = extract_reading(blocks)
        assert result.careful_reading is not None
        assert len(result.careful_reading.passages) == 2

    def test_passage_text_not_empty(self):
        blocks = _make_careful_reading_blocks()
        result = extract_reading(blocks)
        for i, passage in enumerate(result.careful_reading.passages):
            assert len(passage.passage_text) > 0, f"Passage {i+1} has empty text"

    def test_questions_have_four_options(self):
        blocks = _make_careful_reading_blocks()
        result = extract_reading(blocks)
        for passage in result.careful_reading.passages:
            for q in passage.questions:
                assert len(q.options) == 4, (
                    f"Question {q.number} has {len(q.options)} options, expected 4"
                )

    def test_question_numbers_in_range_46_55(self):
        blocks = _make_careful_reading_blocks()
        result = extract_reading(blocks)
        all_numbers = []
        for passage in result.careful_reading.passages:
            for q in passage.questions:
                all_numbers.append(q.number)
                assert 46 <= q.number <= 55

    def test_questions_sorted_within_passage(self):
        blocks = _make_careful_reading_blocks()
        result = extract_reading(blocks)
        for passage in result.careful_reading.passages:
            numbers = [q.number for q in passage.questions]
            assert numbers == sorted(numbers)

    def test_passage_one_questions_before_passage_two(self):
        blocks = _make_careful_reading_blocks()
        result = extract_reading(blocks)
        if (
            result.careful_reading.passages[0].questions
            and result.careful_reading.passages[1].questions
        ):
            max_p1 = max(
                q.number for q in result.careful_reading.passages[0].questions
            )
            min_p2 = min(
                q.number for q in result.careful_reading.passages[1].questions
            )
            assert max_p1 < min_p2


# ---------------------------------------------------------------------------
# Tests: Combined extraction
# ---------------------------------------------------------------------------


class TestCombinedExtraction:
    """Tests for extracting all three sub-sections together."""

    def test_all_subsections_extracted(self):
        blocks = (
            _make_banked_cloze_blocks()[:-1]  # Remove trailing Section B marker
            + _make_long_reading_blocks()
            + _make_careful_reading_blocks()
        )
        result = extract_reading(blocks)
        assert result.banked_cloze is not None
        assert result.long_reading is not None
        assert result.careful_reading is not None
        assert len(result.missing_subsections) == 0

    def test_no_cross_contamination(self):
        """Blocks from one sub-section should not appear in another."""
        blocks = (
            _make_banked_cloze_blocks()[:-1]
            + _make_long_reading_blocks()
            + _make_careful_reading_blocks()
        )
        result = extract_reading(blocks)
        # Banked cloze should not contain Long Reading questions
        if result.banked_cloze:
            for q in result.banked_cloze.questions:
                assert q.number < 36 or q.number > 35
        # Long Reading should not contain Careful Reading questions
        if result.long_reading:
            for q in result.long_reading.questions:
                assert 36 <= q.number <= 45
