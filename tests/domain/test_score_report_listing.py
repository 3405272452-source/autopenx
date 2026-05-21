"""Property test: ScoreReport listing, explanation summary & count equation (task 12.2).

**Property 10: ScoreReport 题目列表、解析摘要与等式恒成立**
**Validates: Requirements 8.1, 8.2**

This module verifies three invariants that must hold for any ScoreReport
produced by ``build_score_report``:

1. **Sorted grades**: ``grades`` are sorted by ``question_id`` ascending.
2. **Explanation summary rules**:
   - Original explanation ≤ 200 chars → shown as-is.
   - Original explanation > 200 chars → truncated to 199 chars + "…".
   - No explanation (empty string) → "无解析".
3. **Count conservation**: ``correct_count + wrong_count + unanswered_count
   == len(grades)`` (total question count).

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from string import ascii_letters, digits

from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import QuestionType, SectionName
from cet4_app.domain.grading.score_report_builder import (
    build_explanation_summary,
    build_score_report,
)
from cet4_app.domain.models.question import Paper, Question, Section, SubSection
from cet4_app.domain.models.score_report import QuestionGrade, ScoreReport


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)

_score_decimal = st.decimals(
    min_value=Decimal("0.01"),
    max_value=Decimal("10.00"),
    places=2,
    allow_nan=False,
    allow_infinity=False,
)

# Explanation text: can be empty, short (≤200), or long (>200)
_explanation_text = st.one_of(
    st.just(""),  # empty → "无解析"
    st.text(min_size=1, max_size=200),  # ≤ 200 → as-is
    st.text(min_size=201, max_size=400),  # > 200 → truncated
)


@st.composite
def _valid_question_for_paper(
    draw: st.DrawFn,
    *,
    question_id: str,
    paper_id: str,
    explanation: str,
) -> Question:
    """Build a valid Question with a specific explanation for testing."""
    score = draw(_score_decimal)
    return Question(
        id=question_id,
        paper_id=paper_id,
        section=SectionName.reading,
        sub_section="careful",
        question_type=QuestionType.reading_careful_choice,
        prompt="What is the answer?",
        options=["Option A", "Option B", "Option C", "Option D"],
        correct_letter="A",
        reference_answer="A",
        explanation=explanation,
        score=score,
        tags=[],
        audio_range=None,
        blank_index=None,
        paragraph_key=None,
        min_words=None,
        max_words=None,
    )


@st.composite
def _paper_with_questions(draw: st.DrawFn) -> tuple[Paper, list[str], list[str]]:
    """Generate a Paper with 2-8 questions, returning (paper, question_ids, explanations).

    Questions have unique sorted IDs and varied explanations (empty, short, long).
    """
    paper_id = draw(_short_ident)
    num_questions = draw(st.integers(min_value=2, max_value=8))

    # Generate unique question_ids
    question_ids = sorted(
        draw(
            st.lists(
                _short_ident,
                min_size=num_questions,
                max_size=num_questions,
                unique=True,
            )
        )
    )

    # Generate explanations for each question
    explanations = draw(
        st.lists(_explanation_text, min_size=num_questions, max_size=num_questions)
    )

    # Build questions
    questions: list[Question] = []
    for qid, explanation in zip(question_ids, explanations):
        q = draw(
            _valid_question_for_paper(
                question_id=qid,
                paper_id=paper_id,
                explanation=explanation,
            )
        )
        questions.append(q)

    # Wrap in Paper structure
    sub_section = SubSection(name="careful", questions=questions)
    section = Section(
        name=SectionName.reading,
        sub_sections=[sub_section],
    )
    paper = Paper(
        paper_id=paper_id,
        paper_set_id="test-set",
        exam_period="2024-12",
        set_index=1,
        paper_pdf_path=None,
        answer_pdf_path=None,
        audio_mp3_path=None,
        audio_status="missing",
        status="ok",
        sections=[section],
        shared_banked_words=[],
        long_reading_paragraphs={},
    )

    return paper, question_ids, explanations


@st.composite
def _objective_grades_for_questions(
    draw: st.DrawFn,
    *,
    question_ids: list[str],
    paper: Paper,
) -> list[QuestionGrade]:
    """Generate objective grades for the given question_ids.

    Each grade has a random status from {ok, cannot-grade, unanswered}
    with consistent is_correct values.
    """
    # Build question map for score lookup
    question_map: dict[str, Question] = {}
    for section in paper.sections:
        for sub_section in section.sub_sections:
            for question in sub_section.questions:
                question_map[question.id] = question

    grades: list[QuestionGrade] = []
    for qid in question_ids:
        status = draw(st.sampled_from(["ok", "cannot-grade", "unanswered"]))
        question = question_map[qid]
        score_max = question.score

        if status == "ok":
            is_correct = draw(st.booleans())
            if is_correct:
                earned_score = score_max
            else:
                earned_score = Decimal("0.00")
        elif status == "cannot-grade":
            is_correct = None
            earned_score = Decimal("0.00")
        else:  # unanswered
            is_correct = False
            earned_score = Decimal("0.00")

        grades.append(
            QuestionGrade(
                question_id=qid,
                is_correct=is_correct,
                status=status,
                earned_score=earned_score,
                score_max=score_max,
                reference_answer="A",
                user_answer="" if status == "unanswered" else "B",
                explanation_summary="",  # will be filled by builder
            )
        )

    return grades


# ---------------------------------------------------------------------------
# Property test: build_explanation_summary rules
# ---------------------------------------------------------------------------


@given(explanation=_explanation_text)
@settings(max_examples=200, deadline=500)
def test_explanation_summary_rules(explanation: str) -> None:
    """build_explanation_summary satisfies the three-branch rule.

    **Validates: Requirements 8.2**

    - Empty explanation → "无解析"
    - Explanation ≤ 200 chars → returned as-is
    - Explanation > 200 chars → truncated to 199 chars + "…" (total ≤ 200)
    """
    summary = build_explanation_summary(explanation)

    # Rule: summary is always ≤ 200 characters
    assert len(summary) <= 200, (
        f"Summary length {len(summary)} exceeds 200: {summary!r}"
    )

    if not explanation:
        # Empty → "无解析"
        assert summary == "无解析"
    elif len(explanation) <= 200:
        # Short → as-is
        assert summary == explanation
    else:
        # Long → truncated to 199 + "…"
        assert summary == explanation[:199] + "…"
        assert len(summary) == 200


# ---------------------------------------------------------------------------
# Property test: ScoreReport grades sorted, summaries correct, counts conserved
# ---------------------------------------------------------------------------


@given(data=st.data())
@settings(max_examples=200, deadline=500)
def test_score_report_listing_and_conservation(data: st.DataObject) -> None:
    """ScoreReport grades are sorted, summaries correct, and counts conserved.

    **Validates: Requirements 8.1, 8.2**

    For any ScoreReport produced by build_score_report:
    1. grades are sorted by question_id ascending
    2. explanation_summary follows the three-branch rule
    3. correct_count + wrong_count + unanswered_count == len(grades)
    """
    paper, question_ids, explanations = data.draw(
        _paper_with_questions(), label="paper_with_questions"
    )
    objective_grades = data.draw(
        _objective_grades_for_questions(question_ids=question_ids, paper=paper),
        label="objective_grades",
    )

    # Build the ScoreReport using the production code
    report = build_score_report(
        sheet_id="test-sheet-001",
        paper_id=paper.paper_id,
        paper=paper,
        objective_grades=objective_grades,
        subjective_grades=[],
        elapsed_seconds=data.draw(
            st.integers(min_value=0, max_value=10000), label="elapsed"
        ),
    )

    # --- Assertion 1: grades sorted by question_id ascending ---
    grade_ids = [g.question_id for g in report.grades]
    assert grade_ids == sorted(grade_ids), (
        f"Grades not sorted by question_id: {grade_ids}"
    )

    # --- Assertion 2: explanation_summary follows the rules ---
    # Build question map for explanation lookup
    question_map: dict[str, Question] = {}
    for section in paper.sections:
        for sub_section in section.sub_sections:
            for question in sub_section.questions:
                question_map[question.id] = question

    for grade in report.grades:
        question = question_map.get(grade.question_id)
        original_explanation = question.explanation if question else ""
        summary = grade.explanation_summary

        # Always ≤ 200 chars
        assert len(summary) <= 200

        if not original_explanation:
            assert summary == "无解析", (
                f"Empty explanation should produce '无解析', got {summary!r}"
            )
        elif len(original_explanation) <= 200:
            assert summary == original_explanation, (
                f"Short explanation should be as-is: "
                f"expected {original_explanation!r}, got {summary!r}"
            )
        else:
            expected = original_explanation[:199] + "…"
            assert summary == expected, (
                f"Long explanation should be truncated: "
                f"expected {expected!r}, got {summary!r}"
            )

    # --- Assertion 3: count conservation equation ---
    total_grades = len(report.grades)
    count_sum = report.correct_count + report.wrong_count + report.unanswered_count
    assert count_sum == total_grades, (
        f"Count conservation failed: "
        f"{report.correct_count} + {report.wrong_count} + "
        f"{report.unanswered_count} = {count_sum} != {total_grades}"
    )
