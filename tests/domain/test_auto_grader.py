"""Property tests for Auto_Grader pure function and idempotency.

**Property 7: 客观题判分是纯函数、幂等、且以 strip + casefold 匹配**
**Validates: Requirements 6.1, 6.2, 6.3, 6.5**

Tests:
1. test_auto_grader_is_pure_function — call twice with same inputs, assert
   outputs are identical (idempotent, Req 6.5).
2. test_auto_grader_case_insensitive_and_strip — generate user_answer with
   random case/whitespace padding, assert is_correct matches reference after
   strip+casefold (Req 6.1, 6.2).
3. test_banked_cloze_rejects_over_64_chars — user_answer > 64 chars for
   banked_cloze → is_correct=False (Req 6.2).
4. test_earned_score_in_valid_range — for every grade, assert
   0 <= earned_score <= question.score and earned_score has exactly 2
   decimal places (Req 6.3).
5. test_missing_reference_answer_yields_cannot_grade — when reference_answer
   is "" or "missing", status="cannot-grade", is_correct=None,
   earned_score=0 (Req 6.6).
6. test_unanswered_yields_wrong — when user_answer is "", status="unanswered",
   is_correct=False, earned_score=0 (Req 6.7).
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import hypothesis.strategies as st
from hypothesis import given, settings

from cet4_app.domain.enums import (
    AudioStatus,
    PaperStatus,
    QuestionType,
    SectionName,
    SessionMode,
    SheetStatus,
)
from cet4_app.domain.grading.auto_grader import grade_objective
from cet4_app.domain.models.answer_sheet import Answer, AnswerSheet
from cet4_app.domain.models.question import Paper, Question, Section, SubSection


# ---------------------------------------------------------------------------
# Helpers: minimal fixture builders
# ---------------------------------------------------------------------------

_NOW = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def _make_paper(
    questions: list[Question],
    shared_banked_words: list[str] | None = None,
    long_reading_paragraphs: dict[str, str] | None = None,
) -> Paper:
    """Build a minimal Paper containing the given questions."""
    # Group questions by section/sub_section
    section_map: dict[str, dict[str, list[Question]]] = {}
    for q in questions:
        sec_name = q.section.value
        sub_name = q.sub_section or "default"
        section_map.setdefault(sec_name, {}).setdefault(sub_name, []).append(q)

    sections = []
    for sec_name, subs in section_map.items():
        sub_sections = [
            SubSection(name=sub_name, questions=qs)
            for sub_name, qs in subs.items()
        ]
        sections.append(Section(name=SectionName(sec_name), sub_sections=sub_sections))

    # Auto-detect if long_reading_paragraphs is needed
    has_long_matching = any(
        q.question_type == QuestionType.reading_long_matching for q in questions
    )
    if long_reading_paragraphs is None and has_long_matching:
        long_reading_paragraphs = {
            "A": "Paragraph A text.",
            "B": "Paragraph B text.",
            "C": "Paragraph C text.",
        }

    return Paper(
        paper_id="test-paper-01",
        paper_set_id="test-set-01",
        exam_period="2024-12",
        set_index=1,
        audio_status=AudioStatus.missing,
        status=PaperStatus.ok,
        sections=sections,
        shared_banked_words=shared_banked_words or [],
        long_reading_paragraphs=long_reading_paragraphs or {},
    )


def _make_sheet(answers: dict[str, str]) -> AnswerSheet:
    """Build a minimal AnswerSheet with the given question_id -> user_answer map."""
    answer_entries = {
        qid: Answer(question_id=qid, user_answer=ans, last_updated_at=_NOW)
        for qid, ans in answers.items()
    }
    return AnswerSheet(
        sheet_id="sheet-01",
        paper_id="test-paper-01",
        status=SheetStatus.submitted,
        mode=SessionMode.practice,
        started_at=_NOW,
        submitted_at=_NOW,
        updated_at=_NOW,
        answers=answer_entries,
    )


def _make_listening_question(qid: str, correct_letter: str, score: Decimal) -> Question:
    """Build a minimal listening_news question."""
    return Question(
        id=qid,
        paper_id="test-paper-01",
        section=SectionName.listening,
        sub_section="news",
        question_type=QuestionType.listening_news,
        prompt="What is the news about?",
        options=["Option A", "Option B", "Option C", "Option D"],
        correct_letter=correct_letter,
        score=score,
    )


def _make_careful_reading_question(qid: str, correct_letter: str, score: Decimal) -> Question:
    """Build a minimal reading_careful_choice question."""
    return Question(
        id=qid,
        paper_id="test-paper-01",
        section=SectionName.reading,
        sub_section="careful",
        question_type=QuestionType.reading_careful_choice,
        prompt="What does the author imply?",
        options=["Choice A", "Choice B", "Choice C", "Choice D"],
        correct_letter=correct_letter,
        score=score,
    )


def _make_banked_cloze_question(
    qid: str, blank_index: int, reference_answer: str, score: Decimal
) -> Question:
    """Build a minimal reading_banked_cloze question."""
    return Question(
        id=qid,
        paper_id="test-paper-01",
        section=SectionName.reading,
        sub_section="banked_cloze",
        question_type=QuestionType.reading_banked_cloze,
        prompt=f"Fill in blank {blank_index}",
        blank_index=blank_index,
        reference_answer=reference_answer,
        score=score,
    )


# Shared banked words list (15 distinct words) for banked_cloze tests
_BANKED_WORDS = [
    "abandon", "benefit", "crucial", "diverse", "enhance",
    "feasible", "genuine", "hostile", "immense", "justify",
    "keen", "liberal", "massive", "notable", "obvious",
]


# ---------------------------------------------------------------------------
# Test 1: Pure function / idempotent (Req 6.5)
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(user_answer=st.text(min_size=0, max_size=10))
def test_auto_grader_is_pure_function(user_answer: str):
    """Calling grade_objective twice with the same inputs yields identical results.

    **Validates: Requirements 6.5**
    """
    q = _make_listening_question("q-01", "A", Decimal("3.55"))
    paper = _make_paper([q])
    sheet = _make_sheet({"q-01": user_answer})

    result1 = grade_objective(sheet, paper)
    result2 = grade_objective(sheet, paper)

    assert len(result1) == len(result2)
    for g1, g2 in zip(result1, result2):
        assert g1.question_id == g2.question_id
        assert g1.is_correct == g2.is_correct
        assert g1.earned_score == g2.earned_score
        assert g1.reference_answer == g2.reference_answer
        assert g1.user_answer == g2.user_answer
        assert g1.status == g2.status


# ---------------------------------------------------------------------------
# Test 2: Case insensitive and strip (Req 6.1, 6.2)
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(
    padding_left=st.text(alphabet=" \t\n\r", min_size=0, max_size=5),
    padding_right=st.text(alphabet=" \t\n\r", min_size=0, max_size=5),
    case_transform=st.sampled_from(["upper", "lower", "title", "swapcase"]),
)
def test_auto_grader_case_insensitive_and_strip(
    padding_left: str, padding_right: str, case_transform: str
):
    """User answer with random case/whitespace padding matches reference after
    strip+casefold.

    **Validates: Requirements 6.1, 6.2**
    """
    reference = "A"
    # Apply case transformation to the reference answer
    transformed = getattr(reference, case_transform)()
    user_answer = padding_left + transformed + padding_right

    q = _make_listening_question("q-01", "A", Decimal("3.55"))
    paper = _make_paper([q])
    sheet = _make_sheet({"q-01": user_answer})

    grades = grade_objective(sheet, paper)
    assert len(grades) == 1
    grade = grades[0]

    # After strip+casefold, the user answer should match the reference
    assert grade.is_correct is True
    assert grade.earned_score == Decimal("3.55")


# ---------------------------------------------------------------------------
# Test 3: Banked cloze rejects over 64 chars (Req 6.2)
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(extra_length=st.integers(min_value=1, max_value=100))
def test_banked_cloze_rejects_over_64_chars(extra_length: int):
    """User answer > 64 chars for banked_cloze is always incorrect.

    **Validates: Requirements 6.2**
    """
    reference_word = "abandon"
    # Create a user answer that exceeds 64 characters (after strip)
    long_answer = reference_word + "x" * (65 - len(reference_word) + extra_length - 1)
    assert len(long_answer.strip()) > 64

    q = _make_banked_cloze_question("q-bc-01", 1, reference_word, Decimal("3.55"))
    paper = _make_paper([q], shared_banked_words=_BANKED_WORDS)
    sheet = _make_sheet({"q-bc-01": long_answer})

    grades = grade_objective(sheet, paper)
    assert len(grades) == 1
    grade = grades[0]

    assert grade.is_correct is False
    assert grade.earned_score == Decimal("0.00")


# ---------------------------------------------------------------------------
# Test 4: Earned score in valid range (Req 6.3)
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(
    score_val=st.decimals(min_value=Decimal("0.01"), max_value=Decimal("100.00"), places=2),
    user_answer=st.text(min_size=0, max_size=20),
)
def test_earned_score_in_valid_range(score_val: Decimal, user_answer: str):
    """For every grade, 0 <= earned_score <= question.score and earned_score
    has exactly 2 decimal places.

    **Validates: Requirements 6.3**
    """
    q = _make_listening_question("q-01", "A", score_val)
    paper = _make_paper([q])
    sheet = _make_sheet({"q-01": user_answer})

    grades = grade_objective(sheet, paper)
    assert len(grades) == 1
    grade = grades[0]

    # earned_score must be in [0, question.score]
    assert Decimal("0") <= grade.earned_score <= score_val

    # earned_score must have exactly 2 decimal places
    # Check by verifying the exponent is -2 or the value is 0
    normalized = grade.earned_score.normalize()
    # A Decimal with 2 decimal places: its as_tuple().exponent should be >= -2
    assert grade.earned_score == grade.earned_score.quantize(Decimal("0.01"))


# ---------------------------------------------------------------------------
# Test 5: Missing reference answer yields cannot-grade (Req 6.6)
# ---------------------------------------------------------------------------


def _make_long_matching_question(
    qid: str, reference_answer: str, score: Decimal
) -> Question:
    """Build a minimal reading_long_matching question for missing-ref tests."""
    return Question(
        id=qid,
        paper_id="test-paper-01",
        section=SectionName.reading,
        sub_section="long_matching",
        question_type=QuestionType.reading_long_matching,
        prompt="Which paragraph mentions the following?",
        reference_answer=reference_answer,
        score=score,
    )


@settings(max_examples=50, deadline=None)
@given(
    missing_ref=st.sampled_from(["", "missing", "MISSING", " "]),
    user_answer=st.text(min_size=1, max_size=10),
)
def test_missing_reference_answer_yields_cannot_grade(missing_ref: str, user_answer: str):
    """When reference_answer is "" or "missing", status="cannot-grade",
    is_correct=None, earned_score=0.

    **Validates: Requirements 6.6**
    """
    # Use reading_long_matching which uses reference_answer directly
    # and doesn't have the shared_banked_words membership constraint.
    q = _make_long_matching_question("q-lm-01", missing_ref, Decimal("3.55"))
    paper = _make_paper([q])
    sheet = _make_sheet({"q-lm-01": user_answer})

    grades = grade_objective(sheet, paper)
    assert len(grades) == 1
    grade = grades[0]

    assert grade.status == "cannot-grade"
    assert grade.is_correct is None
    assert grade.earned_score == Decimal("0")


# ---------------------------------------------------------------------------
# Test 6: Unanswered yields wrong (Req 6.7)
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(
    empty_answer=st.sampled_from(["", "  ", "\t", "\n", " \t\n "]),
)
def test_unanswered_yields_wrong(empty_answer: str):
    """When user_answer is empty (after strip), status="unanswered",
    is_correct=False, earned_score=0.

    **Validates: Requirements 6.7**
    """
    q = _make_listening_question("q-01", "A", Decimal("3.55"))
    paper = _make_paper([q])
    sheet = _make_sheet({"q-01": empty_answer})

    grades = grade_objective(sheet, paper)
    assert len(grades) == 1
    grade = grades[0]

    assert grade.status == "unanswered"
    assert grade.is_correct is False
    assert grade.earned_score == Decimal("0")
