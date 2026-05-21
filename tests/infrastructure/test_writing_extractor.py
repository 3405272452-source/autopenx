"""Tests for infrastructure.pdf.writing_extractor.

Validates that the writing extractor correctly:
- Extracts the essay prompt text from Writing section blocks
- Extracts min_words from various English and Chinese patterns
- Extracts max_words when present, returns None when absent
- Handles edge cases (empty input, no directions marker, etc.)

Requirements: 2.7
"""

from __future__ import annotations

import pytest

from cet4_app.infrastructure.pdf.layout import LayoutBlock
from cet4_app.infrastructure.pdf.writing_extractor import (
    WritingExtractResult,
    extract_writing,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(text: str, page: int = 0) -> LayoutBlock:
    """Create a minimal LayoutBlock for testing."""
    return LayoutBlock(text=text, page=page)


# ---------------------------------------------------------------------------
# Tests: Basic extraction
# ---------------------------------------------------------------------------


class TestBasicExtraction:
    """Test basic writing prompt and word count extraction."""

    def test_empty_blocks_returns_empty_result(self):
        result = extract_writing([])
        assert result == WritingExtractResult()
        assert result.prompt == ""
        assert result.min_words is None
        assert result.max_words is None

    def test_extracts_prompt_after_directions(self):
        blocks = [
            _block("Part I Writing (30 minutes)"),
            _block("Directions: For this part, you are allowed 30 minutes "
                   "to write an essay."),
            _block("Write an essay on the importance of reading."),
        ]
        result = extract_writing(blocks)
        assert "essay" in result.prompt
        assert result.prompt != ""

    def test_extracts_prompt_without_directions_marker(self):
        """When no Directions marker, skip header and use remaining text."""
        blocks = [
            _block("Part I Writing (30 minutes)"),
            _block("Write an essay on the topic of online education."),
        ]
        result = extract_writing(blocks)
        assert "online education" in result.prompt


# ---------------------------------------------------------------------------
# Tests: Minimum word count extraction
# ---------------------------------------------------------------------------


class TestMinWords:
    """Test extraction of minimum word count requirements."""

    def test_at_least_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Write an essay of at least 120 words."),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120

    def test_no_less_than_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Write no less than 120 words on the topic."),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120

    def test_not_less_than_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Your essay should be not less than 150 words."),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 150

    def test_chinese_bu_shao_yu_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: 请写一篇不少于120词的短文。"),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120

    def test_chinese_bu_di_yu_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: 字数不低于120个词。"),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120

    def test_no_min_words_returns_none(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Write an essay on the given topic."),
        ]
        result = extract_writing(blocks)
        assert result.min_words is None


# ---------------------------------------------------------------------------
# Tests: Maximum word count extraction
# ---------------------------------------------------------------------------


class TestMaxWords:
    """Test extraction of maximum word count requirements."""

    def test_no_more_than_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Write no more than 180 words."),
        ]
        result = extract_writing(blocks)
        assert result.max_words == 180

    def test_not_more_than_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Your essay should be not more than 200 words."),
        ]
        result = extract_writing(blocks)
        assert result.max_words == 200

    def test_at_most_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Write at most 180 words."),
        ]
        result = extract_writing(blocks)
        assert result.max_words == 180

    def test_chinese_bu_chao_guo_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: 字数不超过180词。"),
        ]
        result = extract_writing(blocks)
        assert result.max_words == 180

    def test_chinese_bu_duo_yu_pattern(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: 字数不多于180个词。"),
        ]
        result = extract_writing(blocks)
        assert result.max_words == 180

    def test_no_max_words_returns_none(self):
        """CET-4 typically only specifies minimum; max should be None."""
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Write at least 120 words on the topic."),
        ]
        result = extract_writing(blocks)
        assert result.max_words is None

    def test_both_min_and_max_extracted(self):
        blocks = [
            _block("Part I Writing"),
            _block("Directions: Write at least 120 words but no more than "
                   "180 words on the following topic."),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120
        assert result.max_words == 180


# ---------------------------------------------------------------------------
# Tests: Realistic CET-4 scenarios
# ---------------------------------------------------------------------------


class TestRealisticScenarios:
    """Test with realistic CET-4 writing section content."""

    def test_typical_cet4_writing_section(self):
        blocks = [
            _block("Part I Writing (30 minutes)", page=1),
            _block(
                "Directions: For this part, you are allowed 30 minutes to "
                "write an essay on the importance of reading ability and how "
                "to develop it. You should write at least 120 words but no "
                "more than 180 words.",
                page=1,
            ),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120
        assert result.max_words == 180
        assert "importance of reading" in result.prompt

    def test_cet4_writing_only_min_words(self):
        """Most CET-4 papers only specify minimum word count."""
        blocks = [
            _block("Part I Writing (30 minutes)", page=1),
            _block(
                "Directions: For this part, you are allowed 30 minutes to "
                "write an essay. You should write at least 120 words.",
                page=1,
            ),
            _block(
                "Topic: The Importance of Teamwork in the Workplace",
                page=1,
            ),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120
        assert result.max_words is None
        assert "Teamwork" in result.prompt or "essay" in result.prompt

    def test_multi_block_prompt(self):
        """Prompt spread across multiple blocks."""
        blocks = [
            _block("Part I Writing (30 minutes)"),
            _block("Directions: For this part, you are allowed 30 minutes."),
            _block("Write an essay that explains your understanding of"),
            _block("the proverb 'Actions speak louder than words.'"),
            _block("You should write at least 120 words."),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120
        assert "proverb" in result.prompt or "Actions speak" in result.prompt

    def test_word_count_in_separate_block(self):
        """Word count requirement in a different block from directions."""
        blocks = [
            _block("Part I Writing (30 minutes)"),
            _block("Directions: Write an essay on the given topic."),
            _block("Topic: Online Learning vs Traditional Learning"),
            _block("Requirements: at least 120 words"),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_single_block_with_everything(self):
        blocks = [
            _block(
                "Part I Writing (30 minutes)\n"
                "Directions: Write at least 120 words on the topic.\n"
                "Topic: My View on Social Media"
            ),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120

    def test_case_insensitive_directions(self):
        blocks = [
            _block("Part I Writing"),
            _block("DIRECTIONS: Write at least 120 words."),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120
        assert result.prompt != ""

    def test_chinese_colon_in_directions(self):
        """Chinese full-width colon after Directions."""
        blocks = [
            _block("Part I Writing"),
            _block("Directions：请写一篇不少于120词的短文。"),
        ]
        result = extract_writing(blocks)
        assert result.min_words == 120
