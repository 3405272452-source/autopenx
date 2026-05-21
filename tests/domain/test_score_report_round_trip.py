"""Property test: ScoreReport JSON round-trip (task 5.2).

**Property 6: JSON Round_Trip（ScoreReport 部分）**
**Validates: Requirements 13.1, 13.4**

This module verifies that any valid ``ScoreReport`` instance survives a
JSON serialization → deserialization round trip with field-level equality
preserved.

The round-trip assertion is:

    ScoreReport.model_validate(
        report.model_dump(mode="json")
    ).model_dump(mode="json") == report.model_dump(mode="json")

This guarantees that Pydantic's JSON serializer and validator are
symmetric — no data is lost, no fields drift, and no type coercions
introduce inequality (Requirement 13.4).

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from string import ascii_letters, digits

from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import SectionName
from cet4_app.domain.models.score_report import (
    QuestionGrade,
    ScoreReport,
)


# ---------------------------------------------------------------------------
# Inline composite strategies
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)

_score_decimal = st.decimals(
    min_value=Decimal("0.00"),
    max_value=Decimal("100.00"),
    places=2,
    allow_nan=False,
    allow_infinity=False,
)

_datetimes = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31),
    timezones=st.just(timezone.utc),
)

_explanation_summary = st.text(min_size=0, max_size=200)
_answer_text = st.text(min_size=0, max_size=256)


@st.composite
def _valid_question_grade(
    draw: st.DrawFn,
    *,
    question_id: str,
    status: str | None = None,
) -> QuestionGrade:
    """Build a valid QuestionGrade respecting cross-field invariants."""
    if status is None:
        status = draw(
            st.sampled_from(["ok", "cannot-grade", "unanswered", "pending-manual-grade"])
        )

    score_max = draw(_score_decimal)

    # earned_score must be <= score_max
    if score_max == Decimal("0.00"):
        earned_score = Decimal("0.00")
    else:
        earned_score = draw(
            st.decimals(
                min_value=Decimal("0.00"),
                max_value=score_max,
                places=2,
                allow_nan=False,
                allow_infinity=False,
            )
        )

    # Determine is_correct based on status invariants
    if status == "ok":
        is_correct = draw(st.sampled_from([True, False]))
    elif status == "cannot-grade":
        is_correct = None
    elif status == "unanswered":
        is_correct = False
    else:  # pending-manual-grade
        is_correct = draw(st.sampled_from([True, False, None]))

    return QuestionGrade(
        question_id=question_id,
        is_correct=is_correct,
        status=status,
        earned_score=earned_score,
        score_max=score_max,
        reference_answer=draw(_answer_text),
        user_answer=draw(_answer_text),
        explanation_summary=draw(_explanation_summary),
    )


@st.composite
def _valid_score_report(draw: st.DrawFn) -> ScoreReport:
    """Build a valid ScoreReport with consistent cross-field invariants.

    Generates 1-8 QuestionGrade entries with unique, sorted question_ids,
    then derives correct/wrong/unanswered counts and cannot_grade_ids from
    the generated grades to satisfy the model validator.
    """
    report_id = draw(_short_ident)
    sheet_id = draw(_short_ident)
    paper_id = draw(_short_ident)

    # Generate 1-8 unique question_ids, then sort them
    num_grades = draw(st.integers(min_value=1, max_value=8))
    question_ids = sorted(
        draw(
            st.lists(
                _short_ident,
                min_size=num_grades,
                max_size=num_grades,
                unique=True,
            )
        )
    )

    # Build grades with consistent statuses
    grades: list[QuestionGrade] = []
    for qid in question_ids:
        grade = draw(_valid_question_grade(question_id=qid))
        grades.append(grade)

    # Derive counts from grades (must satisfy the invariant)
    correct_count = 0
    wrong_count = 0
    unanswered_count = 0
    cannot_grade_ids: list[str] = []

    for g in grades:
        if g.status == "unanswered":
            unanswered_count += 1
        elif g.status == "ok":
            if g.is_correct:
                correct_count += 1
            else:
                wrong_count += 1
        elif g.status == "cannot-grade":
            cannot_grade_ids.append(g.question_id)
            # cannot-grade counts toward neither correct nor wrong in the
            # summing identity; but the invariant is:
            # correct + wrong + unanswered == len(grades)
            # So we need to account for cannot-grade in one of the buckets.
            # Looking at the model validator: it checks
            # correct_count + wrong_count + unanswered_count == len(grades)
            # So cannot-grade items must be counted somewhere. Since
            # is_correct is None, they are neither correct nor unanswered.
            # They go into wrong_count by convention for the summing identity.
            wrong_count += 1
        elif g.status == "pending-manual-grade":
            # pending-manual-grade: must also be counted in the sum
            if g.is_correct is True:
                correct_count += 1
            elif g.is_correct is False:
                wrong_count += 1
            else:
                # is_correct is None for pending-manual-grade
                wrong_count += 1

    # Section scores: generate for a random subset of sections
    section_scores: dict[SectionName, Decimal] = {}
    for section in draw(
        st.lists(st.sampled_from(list(SectionName)), min_size=0, max_size=4, unique=True)
    ):
        section_scores[section] = draw(_score_decimal)

    total_score = draw(_score_decimal)
    scaled_score_710 = draw(st.integers(min_value=0, max_value=710))
    duration_seconds = draw(st.integers(min_value=0, max_value=100000))
    generated_at = draw(_datetimes)

    return ScoreReport(
        report_id=report_id,
        sheet_id=sheet_id,
        paper_id=paper_id,
        total_score=total_score,
        scaled_score_710=scaled_score_710,
        section_scores=section_scores,
        grades=grades,
        correct_count=correct_count,
        wrong_count=wrong_count,
        unanswered_count=unanswered_count,
        cannot_grade_ids=cannot_grade_ids,
        duration_seconds=duration_seconds,
        generated_at=generated_at,
    )


# ---------------------------------------------------------------------------
# Test: ScoreReport JSON round-trip
# ---------------------------------------------------------------------------


@given(report=_valid_score_report())
@settings(max_examples=200, deadline=500)
def test_score_report_json_round_trip(report: ScoreReport) -> None:
    """Any valid ScoreReport survives JSON round-trip with field equality.

    **Validates: Requirements 13.1, 13.4**

    Dumps the ScoreReport to a JSON-compatible dict, re-validates from that
    dict, and asserts the two JSON representations are identical.
    """
    json_repr = report.model_dump(mode="json")
    report_restored = ScoreReport.model_validate(json_repr)
    json_repr_restored = report_restored.model_dump(mode="json")
    assert json_repr_restored == json_repr
