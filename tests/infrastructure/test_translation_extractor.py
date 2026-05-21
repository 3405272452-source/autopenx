"""Tests for infrastructure.pdf.translation_extractor.

Validates that the translation extractor correctly:
- Extracts Chinese source paragraph(s) from Translation section blocks
- Extracts min_words from various English and Chinese patterns
- Extracts max_words when present, returns None when absent
- Handles edge cases (empty input, no Chinese text, etc.)

Requirements: 2.8
"""

from __future__ import annotations

import pytest

from cet4_app.infrastructure.pdf.layout import LayoutBlock
from cet4_app.infrastructure.pdf.translation_extractor import (
    TranslationExtractResult,
    extract_translation,
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
    """Test basic translation source text and word count extraction."""

    def test_empty_blocks_returns_empty_result(self):
        result = extract_translation([])
        assert result == TranslationExtractResult()
        assert result.source_text == ""
        assert result.min_words is None
        assert result.max_words is None

    def test_extracts_chinese_paragraph(self):
        blocks = [
            _block("Part IV Translation (30 minutes)"),
            _block("Directions: Translate the following paragraph into English."),
            _block("中国是世界上最古老的文明之一，有着悠久的历史和灿烂的文化。"),
        ]
        result = extract_translation(blocks)
        assert "中国" in result.source_text
        assert "文明" in result.source_text

    def test_skips_english_instruction_blocks(self):
        blocks = [
            _block("Part IV Translation (30 minutes)"),
            _block("Directions: Translate the following paragraph into English."),
            _block("中国的茶文化源远流长，已有数千年的历史。茶不仅是一种饮品，更是一种文化象征。"),
        ]
        result = extract_translation(blocks)
        # Should not include the English directions in source_text
        assert "Directions" not in result.source_text
        assert "Part IV" not in result.source_text
        assert "茶文化" in result.source_text


# ---------------------------------------------------------------------------
# Tests: Minimum word count extraction
# ---------------------------------------------------------------------------


class TestMinWords:
    """Test extraction of minimum word count requirements."""

    def test_chinese_bu_shao_yu_pattern(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: 请将下列段落翻译成英文，不少于140词。"),
            _block("中国的高铁技术在世界上处于领先地位，已经成为中国的一张名片。"),
        ]
        result = extract_translation(blocks)
        assert result.min_words == 140

    def test_chinese_bu_di_yu_pattern(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: 翻译不低于140个字。"),
            _block("中国的互联网经济发展迅速，电子商务已经深入人们的日常生活。"),
        ]
        result = extract_translation(blocks)
        assert result.min_words == 140

    def test_english_at_least_pattern(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Translate into at least 140 words."),
            _block("中国的教育体系经历了巨大的变革，从传统的科举制度到现代的高考制度。"),
        ]
        result = extract_translation(blocks)
        assert result.min_words == 140

    def test_no_less_than_pattern(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Your translation should be no less than 140 words."),
            _block("中国的城市化进程在过去几十年中取得了显著的成就。"),
        ]
        result = extract_translation(blocks)
        assert result.min_words == 140

    def test_no_min_words_returns_none(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Translate the following paragraph."),
            _block("中国的传统节日丰富多彩，每个节日都有其独特的文化内涵。"),
        ]
        result = extract_translation(blocks)
        assert result.min_words is None


# ---------------------------------------------------------------------------
# Tests: Maximum word count extraction
# ---------------------------------------------------------------------------


class TestMaxWords:
    """Test extraction of maximum word count requirements."""

    def test_chinese_bu_chao_guo_pattern(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: 翻译不超过160词。"),
            _block("中国的饮食文化博大精深，各地都有自己独特的美食和烹饪方法。"),
        ]
        result = extract_translation(blocks)
        assert result.max_words == 160

    def test_chinese_bu_duo_yu_pattern(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: 字数不多于160个词。"),
            _block("中国的园林艺术有着悠久的历史，是中国传统文化的重要组成部分。"),
        ]
        result = extract_translation(blocks)
        assert result.max_words == 160

    def test_english_no_more_than_pattern(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Translate in no more than 160 words."),
            _block("中国的丝绸之路是古代东西方贸易和文化交流的重要通道。"),
        ]
        result = extract_translation(blocks)
        assert result.max_words == 160

    def test_no_max_words_returns_none(self):
        """CET-4 translation typically only specifies minimum."""
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Translate at least 140 words."),
            _block("中国的长城是世界上最伟大的建筑工程之一。"),
        ]
        result = extract_translation(blocks)
        assert result.max_words is None

    def test_both_min_and_max_extracted(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: 翻译不少于140词，不超过160词。"),
            _block("中国的书法艺术是中华民族独特的文化瑰宝，有着数千年的历史。"),
        ]
        result = extract_translation(blocks)
        assert result.min_words == 140
        assert result.max_words == 160


# ---------------------------------------------------------------------------
# Tests: Chinese paragraph extraction
# ---------------------------------------------------------------------------


class TestChineseParagraphExtraction:
    """Test extraction of Chinese source paragraphs."""

    def test_single_chinese_paragraph(self):
        blocks = [
            _block("Part IV Translation (30 minutes)"),
            _block("Directions: Translate the following paragraph into English."),
            _block("中国是世界上人口最多的国家，拥有五千多年的文明史。"
                   "中华文化博大精深，对世界文明的发展做出了重要贡献。"),
        ]
        result = extract_translation(blocks)
        assert "中国" in result.source_text
        assert "文明" in result.source_text

    def test_multiple_chinese_paragraphs(self):
        blocks = [
            _block("Part IV Translation (30 minutes)"),
            _block("Directions: Translate the following into English."),
            _block("中国的经济发展取得了举世瞩目的成就。改革开放以来，"
                   "中国的国内生产总值持续增长。"),
            _block("中国已经成为世界第二大经济体，在国际贸易中发挥着"
                   "越来越重要的作用。"),
        ]
        result = extract_translation(blocks)
        assert "经济发展" in result.source_text
        assert "第二大经济体" in result.source_text

    def test_mixed_chinese_and_english_blocks(self):
        """Only Chinese blocks should be in source_text."""
        blocks = [
            _block("Part IV Translation (30 minutes)"),
            _block("Directions: Translate the following paragraph into English. "
                   "You should write at least 140 words."),
            _block("Note: Pay attention to grammar and vocabulary."),
            _block("中国的高等教育在过去二十年中经历了快速发展，大学数量和"
                   "在校学生人数都大幅增加。"),
        ]
        result = extract_translation(blocks)
        assert "高等教育" in result.source_text
        # English instruction should not be in source
        assert "Pay attention" not in result.source_text


# ---------------------------------------------------------------------------
# Tests: Realistic CET-4 scenarios
# ---------------------------------------------------------------------------


class TestRealisticScenarios:
    """Test with realistic CET-4 translation section content."""

    def test_typical_cet4_translation(self):
        blocks = [
            _block("Part IV Translation (30 minutes)", page=9),
            _block(
                "Directions: For this part, you are allowed 30 minutes to "
                "translate a passage from Chinese into English. You should "
                "write your answer on Answer Sheet 2.",
                page=9,
            ),
            _block(
                "中国是世界上最古老的文明之一。中国文化对东亚地区产生了"
                "深远的影响。中国的四大发明——造纸术、印刷术、火药和指南针"
                "——对世界文明的发展做出了巨大贡献。",
                page=9,
            ),
        ]
        result = extract_translation(blocks)
        assert "四大发明" in result.source_text
        assert "造纸术" in result.source_text

    def test_cet4_translation_with_word_count(self):
        blocks = [
            _block("Part IV Translation (30 minutes)", page=9),
            _block(
                "Directions: For this part, you are allowed 30 minutes to "
                "translate a passage from Chinese into English. Your "
                "translation should be at least 140 words.",
                page=9,
            ),
            _block(
                "中国的茶文化有着悠久的历史。茶最早起源于中国，后来传播到"
                "世界各地。中国人饮茶不仅是为了解渴，更是一种生活方式和"
                "社交活动。",
                page=9,
            ),
        ]
        result = extract_translation(blocks)
        assert result.min_words == 140
        assert "茶文化" in result.source_text


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_no_chinese_text_falls_back_to_after_directions(self):
        """When no Chinese detected, fall back to content after Directions."""
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Translate the following."),
            _block("Some content that is not Chinese but should be captured."),
        ]
        result = extract_translation(blocks)
        # Fallback should capture something
        assert result.source_text != ""

    def test_single_block_with_chinese(self):
        blocks = [
            _block("中国的互联网用户数量已经超过十亿，是世界上互联网用户最多的国家。"),
        ]
        result = extract_translation(blocks)
        assert "互联网" in result.source_text

    def test_chinese_text_with_numbers_and_punctuation(self):
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Translate the following."),
            _block("2023年，中国的GDP达到了126万亿元人民币，同比增长5.2%。"
                   "这一成就来之不易，体现了中国经济的韧性和活力。"),
        ]
        result = extract_translation(blocks)
        assert "GDP" in result.source_text or "126万亿" in result.source_text

    def test_word_count_in_separate_block_from_chinese(self):
        """Word count requirement in a different block from Chinese text."""
        blocks = [
            _block("Part IV Translation"),
            _block("Directions: Translate the following paragraph."),
            _block("中国的传统医学有着数千年的历史，中医药学是中华民族的瑰宝。"),
            _block("Requirements: 不少于140词"),
        ]
        result = extract_translation(blocks)
        assert result.min_words == 140
        assert "传统医学" in result.source_text
