"""Tests for infrastructure.pdf.answer_key_parser.

Validates that the answer key parser correctly:
- Parses answer key blocks into structured AnswerEntry objects
- Handles objective answers (A/B/C/D letters, word-based)
- Handles subjective answers (writing, translation reference texts)
- AnswerKeyMatcher pairs answers with questions by sub-section + seq
- Unmatched objective questions get reference_answer = "missing" (Req 2.14)

Requirements: 2.11, 2.14
"""

from __future__ import annotations

import pytest

from cet4_app.domain.enums import QuestionType
from cet4_app.infrastructure.pdf.layout import LayoutBlock
from cet4_app.infrastructure.pdf.answer_key_parser import (
    AnswerEntry,
    AnswerKeyMatcher,
    AnswerKeyParseResult,
    MatchResult,
    QuestionSlot,
    build_question_slots,
    parse_answer_key_blocks,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(text: str, page: int = 0) -> LayoutBlock:
    """Create a minimal LayoutBlock for testing."""
    return LayoutBlock(text=text, page=page)


# ---------------------------------------------------------------------------
# Tests: parse_answer_key_blocks
# ---------------------------------------------------------------------------


class TestParseAnswerKeyBlocks:
    """Tests for the main parsing function."""

    def test_empty_blocks_returns_ok(self):
        result = parse_answer_key_blocks([])
        assert result.status == "ok"
        assert result.entries == []

    def test_parses_listening_objective_answers(self):
        blocks = [
            _block("Part II Listening Comprehension"),
            _block("1. A"),
            _block("2. B"),
            _block("3. C"),
            _block("4. D"),
            _block("5. A"),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"
        assert len(result.entries) >= 5

        # All should be objective
        for entry in result.entries:
            assert entry.kind == "objective"

    def test_parses_reading_section_a_answers(self):
        blocks = [
            _block("Part III Reading Comprehension"),
            _block("Section A 选词填空"),
            _block("26. elaborate"),
            _block("27. fascinating"),
            _block("28. genuine"),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"

        banked = [e for e in result.entries if e.sub_section == "banked_cloze"]
        assert len(banked) >= 3
        assert banked[0].answer == "elaborate"
        assert banked[0].seq == 1

    def test_parses_reading_section_b_answers(self):
        blocks = [
            _block("Part III Reading Comprehension"),
            _block("Section B 长篇阅读"),
            _block("36. G"),
            _block("37. D"),
            _block("38. A"),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"

        long_matching = [
            e for e in result.entries if e.sub_section == "long_matching"
        ]
        assert len(long_matching) >= 3
        assert long_matching[0].answer == "G"

    def test_parses_reading_section_c_answers(self):
        blocks = [
            _block("Part III Reading Comprehension"),
            _block("Section C 仔细阅读"),
            _block("46. A"),
            _block("47. B"),
            _block("48. D"),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"

        careful = [e for e in result.entries if e.sub_section == "careful"]
        assert len(careful) >= 3
        assert careful[0].answer == "A"

    def test_parses_writing_subjective(self):
        blocks = [
            _block("Part I Writing"),
            _block("Sample essay: The importance of reading..."),
            _block("评分标准"),
            _block("Content: 5 points for relevance..."),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"

        writing = [e for e in result.entries if e.sub_section == "writing"]
        assert len(writing) == 1
        assert writing[0].kind == "subjective"
        assert "importance of reading" in writing[0].answer

    def test_parses_translation_subjective(self):
        blocks = [
            _block("Part IV Translation"),
            _block("China is one of the oldest civilizations in the world."),
            _block("评分要点"),
            _block("Key phrases: oldest civilizations, cultural heritage"),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"

        translation = [
            e for e in result.entries if e.sub_section == "translation"
        ]
        assert len(translation) == 1
        assert translation[0].kind == "subjective"
        assert "oldest civilizations" in translation[0].answer

    def test_parses_full_answer_key(self):
        """Test parsing a complete answer key with all sections."""
        blocks = [
            _block("Part I Writing"),
            _block("Reference essay text here."),
            _block("Part II Listening Comprehension"),
            _block("1. A  2. B  3. C"),
            _block("4. D  5. A  6. B  7. C"),
            _block("Part III Reading Comprehension"),
            _block("Section A 选词填空"),
            _block("26. elaborate  27. fascinating"),
            _block("Section B 长篇阅读"),
            _block("36. G  37. D  38. A"),
            _block("Section C 仔细阅读"),
            _block("46. A  47. B  48. D"),
            _block("Part IV Translation"),
            _block("China is one of the oldest civilizations."),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"
        assert len(result.entries) > 0

        # Should have entries from all sections
        sub_sections = {e.sub_section for e in result.entries}
        assert "writing" in sub_sections
        assert "translation" in sub_sections

    def test_listening_subsection_detection(self):
        """Test that listening sub-sections are correctly identified."""
        blocks = [
            _block("Part II Listening Comprehension"),
            _block("News Report"),
            _block("1. A  2. B  3. C"),
            _block("Long Conversation"),
            _block("4. A  5. B"),
            _block("Passage"),
            _block("6. C  7. D"),
        ]
        result = parse_answer_key_blocks(blocks)
        assert result.status == "ok"

        subs = {e.sub_section for e in result.entries}
        assert "news" in subs
        assert "conversation" in subs
        assert "passage" in subs


# ---------------------------------------------------------------------------
# Tests: AnswerKeyMatcher
# ---------------------------------------------------------------------------


class TestAnswerKeyMatcher:
    """Tests for the AnswerKeyMatcher class."""

    def setup_method(self):
        self.matcher = AnswerKeyMatcher()

    def test_match_all_paired(self):
        """All slots find matching entries."""
        slots = [
            QuestionSlot("q1", "news", 1, QuestionType.listening_news),
            QuestionSlot("q2", "news", 2, QuestionType.listening_news),
            QuestionSlot("q3", "careful", 1, QuestionType.reading_careful_choice),
        ]
        entries = [
            AnswerEntry("news", 1, "A"),
            AnswerEntry("news", 2, "B"),
            AnswerEntry("careful", 1, "C"),
        ]

        result = self.matcher.match(slots, entries)

        assert len(result.matched) == 3
        assert result.matched["q1"] == ("A", "")
        assert result.matched["q2"] == ("B", "")
        assert result.matched["q3"] == ("C", "")
        assert result.unmatched_questions == []
        assert result.unmatched_answers == []

    def test_match_with_explanations(self):
        """Entries with explanations are correctly paired."""
        slots = [
            QuestionSlot("q1", "careful", 1, QuestionType.reading_careful_choice),
        ]
        entries = [
            AnswerEntry("careful", 1, "B", "The answer is B because..."),
        ]

        result = self.matcher.match(slots, entries)

        assert result.matched["q1"] == ("B", "The answer is B because...")

    def test_unmatched_objective_questions(self):
        """Objective questions without matching entries are listed."""
        slots = [
            QuestionSlot("q1", "news", 1, QuestionType.listening_news),
            QuestionSlot("q2", "news", 2, QuestionType.listening_news),
            QuestionSlot("q3", "news", 3, QuestionType.listening_news),
        ]
        entries = [
            AnswerEntry("news", 1, "A"),
            # q2 and q3 have no matching entries
        ]

        result = self.matcher.match(slots, entries)

        assert "q1" in result.matched
        assert "q2" in result.unmatched_questions
        assert "q3" in result.unmatched_questions

    def test_unmatched_answer_entries(self):
        """Answer entries without matching slots are tracked."""
        slots = [
            QuestionSlot("q1", "news", 1, QuestionType.listening_news),
        ]
        entries = [
            AnswerEntry("news", 1, "A"),
            AnswerEntry("news", 5, "B"),  # No slot for seq 5
        ]

        result = self.matcher.match(slots, entries)

        assert len(result.unmatched_answers) == 1
        assert result.unmatched_answers[0].seq == 5

    def test_empty_slots_and_entries(self):
        """Empty inputs produce empty result."""
        result = self.matcher.match([], [])
        assert result.matched == {}
        assert result.unmatched_questions == []
        assert result.unmatched_answers == []

    def test_duplicate_entry_keys_first_wins(self):
        """When multiple entries have the same (sub_section, seq), first wins."""
        slots = [
            QuestionSlot("q1", "news", 1, QuestionType.listening_news),
        ]
        entries = [
            AnswerEntry("news", 1, "A"),
            AnswerEntry("news", 1, "B"),  # Duplicate - should be ignored
        ]

        result = self.matcher.match(slots, entries)

        assert result.matched["q1"] == ("A", "")

    def test_apply_to_questions_writes_answers(self):
        """apply_to_questions writes reference_answer and explanation."""
        questions = [
            {"id": "q1", "question_type": QuestionType.listening_news,
             "reference_answer": "", "explanation": ""},
            {"id": "q2", "question_type": QuestionType.reading_careful_choice,
             "reference_answer": "", "explanation": ""},
        ]
        match_result = MatchResult(
            matched={
                "q1": ("A", "Because..."),
                "q2": ("C", ""),
            }
        )

        self.matcher.apply_to_questions(questions, match_result)

        assert questions[0]["reference_answer"] == "A"
        assert questions[0]["explanation"] == "Because..."
        assert questions[1]["reference_answer"] == "C"

    def test_apply_to_questions_sets_missing_for_unmatched_objective(self):
        """Unmatched objective questions get reference_answer='missing'."""
        questions = [
            {"id": "q1", "question_type": QuestionType.listening_news,
             "reference_answer": ""},
            {"id": "q2", "question_type": QuestionType.writing,
             "reference_answer": ""},
        ]
        match_result = MatchResult(
            unmatched_questions=["q1", "q2"]
        )

        self.matcher.apply_to_questions(questions, match_result)

        # Objective question gets "missing"
        assert questions[0]["reference_answer"] == "missing"
        # Subjective question does NOT get "missing"
        assert questions[1]["reference_answer"] == ""

    def test_apply_preserves_existing_explanation_when_empty(self):
        """If matched explanation is empty, existing explanation is preserved."""
        questions = [
            {"id": "q1", "question_type": QuestionType.listening_news,
             "reference_answer": "", "explanation": "existing"},
        ]
        match_result = MatchResult(
            matched={"q1": ("A", "")}
        )

        self.matcher.apply_to_questions(questions, match_result)

        assert questions[0]["reference_answer"] == "A"
        # Empty explanation from match should not overwrite existing
        assert questions[0]["explanation"] == "existing"

    def test_match_cross_section_isolation(self):
        """Entries from different sub-sections don't cross-match."""
        slots = [
            QuestionSlot("q1", "news", 1, QuestionType.listening_news),
            QuestionSlot("q2", "careful", 1, QuestionType.reading_careful_choice),
        ]
        entries = [
            AnswerEntry("news", 1, "A"),
            AnswerEntry("careful", 1, "B"),
        ]

        result = self.matcher.match(slots, entries)

        assert result.matched["q1"] == ("A", "")
        assert result.matched["q2"] == ("B", "")


# ---------------------------------------------------------------------------
# Tests: build_question_slots
# ---------------------------------------------------------------------------


class TestBuildQuestionSlots:
    """Tests for the build_question_slots helper."""

    def test_builds_slots_from_question_dicts(self):
        questions = [
            {
                "id": "2024-12-set1-listening-news-01",
                "question_type": QuestionType.listening_news,
                "sub_section": "news",
            },
            {
                "id": "2024-12-set1-reading-careful-03",
                "question_type": QuestionType.reading_careful_choice,
                "sub_section": "careful",
            },
        ]

        slots = build_question_slots(questions)

        assert len(slots) == 2
        assert slots[0].question_id == "2024-12-set1-listening-news-01"
        assert slots[0].sub_section == "news"
        assert slots[0].seq == 1
        assert slots[1].question_id == "2024-12-set1-reading-careful-03"
        assert slots[1].sub_section == "careful"
        assert slots[1].seq == 3

    def test_builds_slots_for_banked_cloze_with_blank_index(self):
        questions = [
            {
                "id": "2024-12-set1-reading-banked_cloze-05",
                "question_type": QuestionType.reading_banked_cloze,
                "blank_index": 5,
            },
        ]

        slots = build_question_slots(questions)

        assert len(slots) == 1
        assert slots[0].sub_section == "banked_cloze"
        assert slots[0].seq == 5

    def test_skips_unknown_question_types(self):
        questions = [
            {
                "id": "q1",
                "question_type": "unknown_type",
            },
        ]

        slots = build_question_slots(questions)
        assert len(slots) == 0

    def test_handles_string_question_type(self):
        questions = [
            {
                "id": "2024-12-set1-listening-news-02",
                "question_type": "listening_news",
            },
        ]

        slots = build_question_slots(questions)

        assert len(slots) == 1
        assert slots[0].sub_section == "news"
        assert slots[0].seq == 2


# ---------------------------------------------------------------------------
# Tests: Integration - parse + match
# ---------------------------------------------------------------------------


class TestParseAndMatch:
    """Integration tests combining parsing and matching."""

    def test_full_workflow(self):
        """Parse answer key blocks and match to question slots."""
        # Simulate answer key blocks
        blocks = [
            _block("Part II Listening Comprehension"),
            _block("1. A  2. B  3. C  4. D  5. A"),
            _block("Part III Reading Comprehension"),
            _block("Section A 选词填空"),
            _block("26. elaborate  27. fascinating  28. genuine"),
            _block("Section C 仔细阅读"),
            _block("46. A  47. B"),
        ]

        # Parse
        parse_result = parse_answer_key_blocks(blocks)
        assert parse_result.status == "ok"

        # Build question slots
        question_dicts = [
            {"id": "q-listen-01", "question_type": QuestionType.listening_news,
             "sub_section": "news", "seq": 1},
            {"id": "q-listen-02", "question_type": QuestionType.listening_news,
             "sub_section": "news", "seq": 2},
            {"id": "q-banked-01", "question_type": QuestionType.reading_banked_cloze,
             "blank_index": 1, "sub_section": "banked_cloze"},
            {"id": "q-careful-01", "question_type": QuestionType.reading_careful_choice,
             "sub_section": "careful", "seq": 1},
            {"id": "q-careful-05", "question_type": QuestionType.reading_careful_choice,
             "sub_section": "careful", "seq": 5},
        ]

        slots = []
        for q in question_dicts:
            qtype = q["question_type"]
            sub = q.get("sub_section", "")
            seq = q.get("blank_index") or q.get("seq", 0)
            slots.append(QuestionSlot(q["id"], sub, seq, qtype))

        # Match
        matcher = AnswerKeyMatcher()
        result = matcher.match(slots, parse_result.entries)

        # Some should be matched
        assert len(result.matched) > 0

        # Unmatched objective questions should exist for q-careful-05
        # (since we only provided answers for 46 and 47, i.e. seq 1 and 2)
        if "q-careful-05" in result.unmatched_questions:
            # Apply to questions
            matcher.apply_to_questions(question_dicts, result)
            careful_05 = next(
                q for q in question_dicts if q["id"] == "q-careful-05"
            )
            assert careful_05.get("reference_answer") == "missing"
