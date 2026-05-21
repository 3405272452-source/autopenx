"""Tests for infrastructure.pdf.section_splitter.

Validates that the section splitter correctly:
- Splits blocks into 4 sections using Part I/II/III/IV anchors
- Marks sections as needs-review when their anchor is missing
- Handles edge cases (empty input, all anchors missing, partial anchors)

Requirements: 2.1, 2.10
"""

from __future__ import annotations

import pytest

from cet4_app.domain.enums import SectionName
from cet4_app.infrastructure.pdf.layout import LayoutBlock
from cet4_app.infrastructure.pdf.section_splitter import (
    SectionSplit,
    SplitResult,
    split_sections,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(text: str, page: int = 0) -> LayoutBlock:
    """Create a minimal LayoutBlock for testing."""
    return LayoutBlock(text=text, page=page)


def _make_full_paper_blocks() -> list[LayoutBlock]:
    """Create a realistic sequence of blocks for a complete CET-4 paper."""
    return [
        _block("CET-4 Examination Paper", page=0),
        _block("Part I Writing (30 minutes)", page=1),
        _block("Directions: For this part...", page=1),
        _block("Write an essay on the topic...", page=1),
        _block("Part II Listening Comprehension (25 minutes)", page=2),
        _block("Section A News Report", page=2),
        _block("1. A) option A  B) option B", page=2),
        _block("Part III Reading Comprehension (40 minutes)", page=5),
        _block("Section A Banked Cloze", page=5),
        _block("Section B Long Reading", page=6),
        _block("Section C Careful Reading", page=7),
        _block("Part IV Translation (30 minutes)", page=9),
        _block("Directions: Translate the following...", page=9),
        _block("中国是世界上最古老的文明之一。", page=9),
    ]


# ---------------------------------------------------------------------------
# Tests: Full paper with all anchors present
# ---------------------------------------------------------------------------


class TestFullPaper:
    """All four anchors are present in the correct order."""

    def test_all_sections_found(self):
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        assert isinstance(result, SplitResult)
        assert len(result.sections) == 4
        assert result.missing_anchors == []

    def test_no_section_needs_review(self):
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        for name in SectionName:
            assert result.sections[name].needs_review is False

    def test_writing_section_blocks(self):
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        writing = result.sections[SectionName.writing]
        assert len(writing.blocks) == 3  # Part I header + 2 content blocks
        assert "Writing" in writing.blocks[0].text

    def test_listening_section_blocks(self):
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        listening = result.sections[SectionName.listening]
        assert len(listening.blocks) == 3
        assert "Listening" in listening.blocks[0].text

    def test_reading_section_blocks(self):
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        reading = result.sections[SectionName.reading]
        assert len(reading.blocks) == 4
        assert "Reading" in reading.blocks[0].text

    def test_translation_section_blocks(self):
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        translation = result.sections[SectionName.translation]
        assert len(translation.blocks) == 3
        assert "Translation" in translation.blocks[0].text

    def test_blocks_before_first_anchor_discarded(self):
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        # The cover page block should not appear in any section
        all_section_blocks = []
        for section in result.sections.values():
            all_section_blocks.extend(section.blocks)

        cover_texts = [b.text for b in all_section_blocks]
        assert "CET-4 Examination Paper" not in cover_texts


# ---------------------------------------------------------------------------
# Tests: Missing anchors → needs-review
# ---------------------------------------------------------------------------


class TestMissingAnchors:
    """When anchors are missing, corresponding sections get needs-review."""

    def test_missing_writing_anchor(self):
        blocks = [
            _block("Some preamble"),
            _block("Part II Listening Comprehension (25 minutes)"),
            _block("Listening content"),
            _block("Part III Reading Comprehension (40 minutes)"),
            _block("Reading content"),
            _block("Part IV Translation (30 minutes)"),
            _block("Translation content"),
        ]
        result = split_sections(blocks)

        assert SectionName.writing in result.missing_anchors
        assert result.sections[SectionName.writing].needs_review is True
        assert result.sections[SectionName.writing].blocks == []

        # Other sections should be fine
        assert result.sections[SectionName.listening].needs_review is False
        assert result.sections[SectionName.reading].needs_review is False
        assert result.sections[SectionName.translation].needs_review is False

    def test_missing_listening_anchor(self):
        blocks = [
            _block("Part I Writing (30 minutes)"),
            _block("Writing content"),
            _block("Part III Reading Comprehension (40 minutes)"),
            _block("Reading content"),
            _block("Part IV Translation (30 minutes)"),
            _block("Translation content"),
        ]
        result = split_sections(blocks)

        assert SectionName.listening in result.missing_anchors
        assert result.sections[SectionName.listening].needs_review is True
        assert result.sections[SectionName.listening].blocks == []

        # Writing should include blocks up to Reading anchor
        assert result.sections[SectionName.writing].needs_review is False
        assert len(result.sections[SectionName.writing].blocks) == 2

    def test_missing_multiple_anchors(self):
        blocks = [
            _block("Part I Writing (30 minutes)"),
            _block("Writing content"),
            _block("Part IV Translation (30 minutes)"),
            _block("Translation content"),
        ]
        result = split_sections(blocks)

        assert SectionName.listening in result.missing_anchors
        assert SectionName.reading in result.missing_anchors
        assert len(result.missing_anchors) == 2

        assert result.sections[SectionName.writing].needs_review is False
        assert result.sections[SectionName.translation].needs_review is False
        assert result.sections[SectionName.listening].needs_review is True
        assert result.sections[SectionName.reading].needs_review is True

    def test_all_anchors_missing(self):
        blocks = [
            _block("Some random text"),
            _block("More random text"),
        ]
        result = split_sections(blocks)

        assert len(result.missing_anchors) == 4
        for name in SectionName:
            assert result.sections[name].needs_review is True
            assert result.sections[name].blocks == []


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_input(self):
        result = split_sections([])

        assert len(result.sections) == 4
        assert len(result.missing_anchors) == 4
        for name in SectionName:
            assert result.sections[name].needs_review is True
            assert result.sections[name].blocks == []

    def test_case_insensitive_matching(self):
        blocks = [
            _block("PART I WRITING"),
            _block("Content"),
            _block("part ii listening comprehension"),
            _block("Content"),
            _block("Part III READING COMPREHENSION"),
            _block("Content"),
            _block("PART IV translation"),
            _block("Content"),
        ]
        result = split_sections(blocks)

        assert result.missing_anchors == []
        for name in SectionName:
            assert result.sections[name].needs_review is False

    def test_flexible_whitespace_in_anchors(self):
        blocks = [
            _block("Part  I  Writing"),
            _block("Content"),
            _block("Part   II   Listening   Comprehension"),
            _block("Content"),
            _block("PartIII Reading Comprehension"),  # No space between Part and III
            _block("Content"),
            _block("Part  IV  Translation"),
            _block("Content"),
        ]
        result = split_sections(blocks)

        # Part III without space should still match (Part\s*III)
        assert SectionName.reading not in result.missing_anchors
        assert result.sections[SectionName.writing].needs_review is False
        assert result.sections[SectionName.listening].needs_review is False
        assert result.sections[SectionName.translation].needs_review is False

    def test_anchor_in_middle_of_text(self):
        """Anchor pattern found within a longer text block."""
        blocks = [
            _block("Instructions: Part I Writing (30 minutes)"),
            _block("Write an essay..."),
            _block("Now begin Part II Listening Comprehension section"),
            _block("Listen carefully..."),
            _block("Section: Part III Reading Comprehension (40 min)"),
            _block("Read the passages..."),
            _block("Final: Part IV Translation (30 minutes)"),
            _block("Translate..."),
        ]
        result = split_sections(blocks)

        assert result.missing_anchors == []
        for name in SectionName:
            assert result.sections[name].needs_review is False

    def test_only_one_section_present(self):
        """Only translation anchor found."""
        blocks = [
            _block("Random preamble"),
            _block("Part IV Translation (30 minutes)"),
            _block("Translation content line 1"),
            _block("Translation content line 2"),
        ]
        result = split_sections(blocks)

        assert len(result.missing_anchors) == 3
        assert SectionName.translation not in result.missing_anchors
        assert result.sections[SectionName.translation].needs_review is False
        assert len(result.sections[SectionName.translation].blocks) == 3

    def test_section_split_preserves_block_order(self):
        """Blocks within a section maintain their original order."""
        blocks = _make_full_paper_blocks()
        result = split_sections(blocks)

        reading = result.sections[SectionName.reading]
        texts = [b.text for b in reading.blocks]
        assert texts[0].startswith("Part III")
        assert "Section A" in texts[1]
        assert "Section B" in texts[2]
        assert "Section C" in texts[3]

    def test_result_always_has_all_four_sections(self):
        """SplitResult always contains entries for all four section names."""
        # Even with partial input
        blocks = [_block("Part I Writing"), _block("content")]
        result = split_sections(blocks)

        assert set(result.sections.keys()) == set(SectionName)
