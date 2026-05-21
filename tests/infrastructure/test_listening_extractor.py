"""Tests for infrastructure.pdf.listening_extractor.

Validates that the listening extractor correctly:
- Splits listening blocks into News Report / Long Conversation / Passage groups
- Extracts questions with 4 options each
- Assigns audio_range using time markers (priority) or word-count estimation
- Handles edge cases (empty input, missing anchors, partial data)

Requirements: 2.6, 5.5
"""

from __future__ import annotations

import pytest

from cet4_app.infrastructure.pdf.layout import LayoutBlock
from cet4_app.infrastructure.pdf.listening_extractor import (
    ListeningExtractResult,
    ListeningGroup,
    ListeningQuestion,
    extract_listening,
    _parse_time_marker,
    _estimate_duration_from_word_count,
    _extract_options_from_text,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(text: str, page: int = 0) -> LayoutBlock:
    """Create a minimal LayoutBlock for testing."""
    return LayoutBlock(text=text, page=page)


def _make_listening_blocks() -> list[LayoutBlock]:
    """Create a realistic sequence of blocks for a CET-4 Listening section."""
    return [
        _block("Part II Listening Comprehension (25 minutes)", page=2),
        _block("Section A", page=2),
        _block("Directions: In this section, you will hear...", page=2),
        _block("News Report One", page=2),
        _block("1. What happened in the news report?", page=2),
        _block("A) A fire broke out\nB) A flood occurred\nC) An earthquake hit\nD) A storm arrived", page=2),
        _block("2. What was the result?", page=3),
        _block("A) No casualties\nB) Minor injuries\nC) Major damage\nD) Complete destruction", page=3),
        _block("News Report Two", page=3),
        _block("3. What is the report about?", page=3),
        _block("A) Technology\nB) Education\nC) Healthcare\nD) Environment", page=3),
        _block("4. What did the experts suggest?", page=3),
        _block("A) More research\nB) New policies\nC) Better funding\nD) Public awareness", page=3),
        _block("News Report Three", page=4),
        _block("5. What was discovered?", page=4),
        _block("A) A new species\nB) An ancient city\nC) A rare mineral\nD) A lost artifact", page=4),
        _block("6. Where was it found?", page=4),
        _block("A) In the ocean\nB) In a cave\nC) In a forest\nD) In a desert", page=4),
        _block("7. Who made the discovery?", page=4),
        _block("A) Scientists\nB) Explorers\nC) Students\nD) Farmers", page=4),
        _block("Conversation One", page=5),
        _block("8. What are the speakers discussing?", page=5),
        _block("A) A project\nB) A vacation\nC) A meeting\nD) A deadline", page=5),
        _block("9. What does the man suggest?", page=5),
        _block("A) Postpone it\nB) Cancel it\nC) Reschedule it\nD) Continue it", page=5),
        _block("10. What will the woman do next?", page=5),
        _block("A) Call the boss\nB) Send an email\nC) Write a report\nD) Attend a meeting", page=5),
        _block("11. When will they meet again?", page=5),
        _block("A) Monday\nB) Tuesday\nC) Wednesday\nD) Thursday", page=5),
        _block("Conversation Two", page=6),
        _block("12. What is the woman's problem?", page=6),
        _block("A) Lost keys\nB) Missed bus\nC) Late for work\nD) Forgot password", page=6),
        _block("13. How does the man help?", page=6),
        _block("A) Gives a ride\nB) Lends money\nC) Makes a call\nD) Offers advice", page=6),
        _block("14. What is the outcome?", page=6),
        _block("A) Problem solved\nB) Still waiting\nC) Need more help\nD) Give up", page=6),
        _block("15. What do they agree on?", page=6),
        _block("A) Meet later\nB) Try again\nC) Ask someone else\nD) Forget about it", page=6),
        _block("Passage One", page=7),
        _block("16. What is the main topic?", page=7),
        _block("A) Climate change\nB) Space exploration\nC) Ocean pollution\nD) Forest conservation", page=7),
        _block("17. What evidence is presented?", page=7),
        _block("A) Statistics\nB) Interviews\nC) Experiments\nD) Observations", page=7),
        _block("18. What conclusion is drawn?", page=7),
        _block("A) Urgent action needed\nB) More study required\nC) Problem overstated\nD) Solution found", page=7),
        _block("Passage Two", page=8),
        _block("19. What does the passage describe?", page=8),
        _block("A) A historical event\nB) A scientific theory\nC) A social trend\nD) A cultural practice", page=8),
        _block("20. What is the author's attitude?", page=8),
        _block("A) Supportive\nB) Critical\nC) Neutral\nD) Indifferent", page=8),
        _block("21. What example is given?", page=8),
        _block("A) A case study\nB) A personal story\nC) A comparison\nD) A definition", page=8),
        _block("22. What is suggested for the future?", page=8),
        _block("A) More investment\nB) Policy changes\nC) Education reform\nD) Technology adoption", page=8),
        _block("Passage Three", page=9),
        _block("23. What problem is discussed?", page=9),
        _block("A) Unemployment\nB) Pollution\nC) Poverty\nD) Inequality", page=9),
        _block("24. What solution is proposed?", page=9),
        _block("A) Government intervention\nB) Private sector\nC) Community effort\nD) Individual action", page=9),
        _block("25. What is the final message?", page=9),
        _block("A) Hope for change\nB) Need for patience\nC) Call to action\nD) Acceptance of reality", page=9),
    ]


# ---------------------------------------------------------------------------
# Tests: Time marker parsing
# ---------------------------------------------------------------------------


class TestTimeMarkerParsing:
    """Test the time marker parsing utility."""

    def test_parse_simple_time(self):
        assert _parse_time_marker("[1:23]") == 83.0

    def test_parse_two_digit_minutes(self):
        assert _parse_time_marker("[12:05]") == 725.0

    def test_parse_zero_padded(self):
        assert _parse_time_marker("[01:23]") == 83.0

    def test_parse_with_fraction(self):
        result = _parse_time_marker("[1:23.5]")
        assert result is not None
        assert abs(result - 83.5) < 0.01

    def test_no_time_marker(self):
        assert _parse_time_marker("No time here") is None

    def test_time_marker_in_context(self):
        assert _parse_time_marker("Question starts at [2:30] in the audio") == 150.0


# ---------------------------------------------------------------------------
# Tests: Word count duration estimation
# ---------------------------------------------------------------------------


class TestWordCountEstimation:
    """Test the word-count-based duration estimation."""

    def test_empty_text(self):
        assert _estimate_duration_from_word_count("") == 0.0

    def test_twelve_words(self):
        text = "one two three four five six seven eight nine ten eleven twelve"
        result = _estimate_duration_from_word_count(text)
        assert abs(result - 1.0) < 0.01

    def test_120_words(self):
        text = " ".join(["word"] * 120)
        result = _estimate_duration_from_word_count(text)
        assert abs(result - 10.0) < 0.01


# ---------------------------------------------------------------------------
# Tests: Option extraction
# ---------------------------------------------------------------------------


class TestOptionExtraction:
    """Test extracting A/B/C/D options from text."""

    def test_parenthesis_format(self):
        text = "A) First option\nB) Second option\nC) Third option\nD) Fourth option"
        options = _extract_options_from_text(text)
        assert len(options) == 4
        assert options[0] == "First option"
        assert options[3] == "Fourth option"

    def test_dot_format(self):
        text = "A. First option\nB. Second option\nC. Third option\nD. Fourth option"
        options = _extract_options_from_text(text)
        assert len(options) == 4
        assert options[0] == "First option"

    def test_no_options(self):
        text = "Just some regular text without options"
        options = _extract_options_from_text(text)
        assert options == []

    def test_incomplete_options(self):
        text = "A) First\nB) Second"
        options = _extract_options_from_text(text)
        assert options == []  # Need all 4


# ---------------------------------------------------------------------------
# Tests: Full extraction
# ---------------------------------------------------------------------------


class TestFullExtraction:
    """Test the complete listening extraction pipeline."""

    def test_extracts_all_groups(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        assert isinstance(result, ListeningExtractResult)
        # Should find news reports, conversations, and passages
        assert len(result.groups) > 0

        # Check sub-section types are present
        types = {g.sub_section_type for g in result.groups}
        assert "news_report" in types
        assert "long_conversation" in types
        assert "passage" in types

    def test_news_report_groups(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        news_groups = [g for g in result.groups if g.sub_section_type == "news_report"]
        assert len(news_groups) == 3

    def test_conversation_groups(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        conv_groups = [g for g in result.groups if g.sub_section_type == "long_conversation"]
        assert len(conv_groups) == 2

    def test_passage_groups(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        passage_groups = [g for g in result.groups if g.sub_section_type == "passage"]
        assert len(passage_groups) == 3

    def test_questions_have_four_options(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        for group in result.groups:
            for q in group.questions:
                if q.options:  # Some questions may not have parsed options
                    assert len(q.options) == 4, (
                        f"Question {q.question_number} has {len(q.options)} options"
                    )

    def test_total_question_count(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        assert result.total_questions == 25

    def test_25_questions_no_needs_review(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        # With exactly 25 questions, needs_review should be False
        assert result.needs_review is False


# ---------------------------------------------------------------------------
# Tests: Audio range computation
# ---------------------------------------------------------------------------


class TestAudioRange:
    """Test audio range assignment logic."""

    def test_group_audio_range_assigned(self):
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        for group in result.groups:
            # Every group should have a group-level audio range
            assert group.group_audio_start_s is not None
            assert group.group_audio_end_s is not None
            assert group.group_audio_end_s > group.group_audio_start_s

    def test_time_marker_priority(self):
        """Questions with time markers should use them for audio_range."""
        blocks = [
            _block("News Report One"),
            _block("[0:30] 1. What happened?"),
            _block("A) Option A\nB) Option B\nC) Option C\nD) Option D"),
            _block("[1:15] 2. What was the result?"),
            _block("A) Option A\nB) Option B\nC) Option C\nD) Option D"),
        ]
        result = extract_listening(blocks)

        assert len(result.groups) >= 1
        group = result.groups[0]

        # Questions with time markers should have audio_range_start_s set
        time_marked_qs = [q for q in group.questions if q.audio_range_start_s is not None]
        assert len(time_marked_qs) >= 1

    def test_no_time_markers_uses_estimation(self):
        """Without time markers, group-level estimation is used."""
        blocks = [
            _block("News Report One"),
            _block("1. What happened in the news?"),
            _block("A) Fire\nB) Flood\nC) Storm\nD) Earthquake"),
            _block("2. What was the outcome?"),
            _block("A) Good\nB) Bad\nC) Neutral\nD) Unknown"),
        ]
        result = extract_listening(blocks)

        assert len(result.groups) >= 1
        group = result.groups[0]

        # Group should have estimated audio range
        assert group.group_audio_start_s is not None
        assert group.group_audio_end_s is not None

        # Individual questions should NOT have audio_range (Req 5.5 fallback)
        for q in group.questions:
            assert q.audio_range_start_s is None

    def test_cumulative_offset_increases(self):
        """Each group's start should be >= previous group's end."""
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        prev_end = 0.0
        for group in result.groups:
            assert group.group_audio_start_s is not None
            assert group.group_audio_start_s >= prev_end - 0.01  # small tolerance
            if group.group_audio_end_s is not None:
                prev_end = group.group_audio_end_s


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_input(self):
        result = extract_listening([])
        assert result.total_questions == 0
        assert result.needs_review is True
        assert result.groups == []

    def test_no_anchors_found(self):
        """When no sub-section anchors are found, fallback extraction is used."""
        blocks = [
            _block("1. What is the topic?"),
            _block("A) Science\nB) Art\nC) Music\nD) Sports"),
            _block("2. Who is speaking?"),
            _block("A) Teacher\nB) Student\nC) Doctor\nD) Engineer"),
        ]
        result = extract_listening(blocks)

        # Should still extract questions via fallback
        assert result.total_questions >= 1
        assert result.needs_review is True

    def test_unexpected_question_count_marks_needs_review(self):
        """If total questions != 25, needs_review should be True."""
        blocks = [
            _block("News Report One"),
            _block("1. Question one?"),
            _block("A) A\nB) B\nC) C\nD) D"),
        ]
        result = extract_listening(blocks)

        assert result.total_questions != 25
        assert result.needs_review is True

    def test_group_index_assignment(self):
        """Groups should have correct 1-based indices."""
        blocks = _make_listening_blocks()
        result = extract_listening(blocks)

        news_groups = [g for g in result.groups if g.sub_section_type == "news_report"]
        for i, group in enumerate(news_groups, 1):
            assert group.group_index == i
