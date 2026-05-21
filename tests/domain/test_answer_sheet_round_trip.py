"""Property test: AnswerSheet JSON round-trip (task 4.2).

**Property 6: JSON Round_Trip（AnswerSheet 部分）**
**Validates: Requirements 13.1, 13.3**

This module verifies that any valid ``AnswerSheet`` instance survives a
JSON serialization → deserialization round trip with field-level equality
preserved.

The round-trip assertion is:

    AnswerSheet.model_validate(sheet.model_dump(mode="json")).model_dump(mode="json")
        == sheet.model_dump(mode="json")

This guarantees that Pydantic's JSON serializer and validator are
symmetric for the AnswerSheet model — no data is lost, no fields drift,
and no type coercions introduce inequality (Requirement 13.3).

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from string import ascii_letters, digits

from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import SessionMode, SheetStatus
from cet4_app.domain.models.answer_sheet import (
    Answer,
    AnswerSheet,
    RubricScore,
)


# ---------------------------------------------------------------------------
# Leaf strategies
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)

# Datetime strategy: generate timezone-aware datetimes within a reasonable
# range to avoid edge cases with extreme years that may not round-trip
# cleanly through ISO-8601 string serialization.
_datetime_st = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31),
    timezones=st.just(timezone.utc),
)


# ---------------------------------------------------------------------------
# Inline composite strategy for a valid AnswerSheet
# ---------------------------------------------------------------------------


@st.composite
def _valid_rubric_score(draw: st.DrawFn) -> RubricScore:
    """Generate a valid RubricScore with all dimensions in [0, 5]."""
    return RubricScore(
        content=draw(st.integers(min_value=0, max_value=5)),
        structure=draw(st.integers(min_value=0, max_value=5)),
        language=draw(st.integers(min_value=0, max_value=5)),
        word_count=draw(st.integers(min_value=0, max_value=5)),
    )


@st.composite
def _valid_answer(draw: st.DrawFn) -> Answer:
    """Generate a valid Answer instance."""
    return Answer(
        question_id=draw(st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=64)),
        user_answer=draw(st.text(min_size=0, max_size=128)),
        last_updated_at=draw(_datetime_st),
        rubric=draw(st.one_of(st.none(), _valid_rubric_score())),
        ai_result_id=draw(
            st.one_of(
                st.none(),
                st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=32),
            )
        ),
    )


@st.composite
def _valid_answer_sheet(draw: st.DrawFn) -> AnswerSheet:
    """Generate a valid AnswerSheet respecting all cross-field invariants.

    The strategy carefully handles the lifecycle constraints:
    - status=submitted requires submitted_at to be set
    - mode=mock_exam with status!=submitted requires mock_deadline to be set
    """
    sheet_id = draw(_short_ident)
    paper_id = draw(_short_ident)
    status = draw(st.sampled_from(list(SheetStatus)))
    mode = draw(st.sampled_from(list(SessionMode)))
    started_at = draw(_datetime_st)
    updated_at = draw(_datetime_st)
    elapsed_seconds = draw(st.integers(min_value=0, max_value=10000))

    # Handle submitted_at based on status constraint
    if status == SheetStatus.submitted:
        submitted_at = draw(_datetime_st)
    else:
        submitted_at = draw(st.one_of(st.none(), _datetime_st))

    # Handle mock_deadline based on mode + status constraint
    if mode == SessionMode.mock_exam and status != SheetStatus.submitted:
        mock_deadline = draw(_datetime_st)
    else:
        mock_deadline = draw(st.one_of(st.none(), _datetime_st))

    draft_saved_at = draw(st.one_of(st.none(), _datetime_st))

    # Generate 0..5 answers with unique question_ids
    num_answers = draw(st.integers(min_value=0, max_value=5))
    answers: dict[str, Answer] = {}
    for i in range(num_answers):
        answer = draw(_valid_answer())
        # Ensure unique question_id keys in the dict
        key = f"q-{i:03d}-{answer.question_id[:10]}"
        answer_with_key = Answer(
            question_id=key,
            user_answer=answer.user_answer,
            last_updated_at=answer.last_updated_at,
            rubric=answer.rubric,
            ai_result_id=answer.ai_result_id,
        )
        answers[key] = answer_with_key

    return AnswerSheet(
        sheet_id=sheet_id,
        paper_id=paper_id,
        status=status,
        mode=mode,
        started_at=started_at,
        submitted_at=submitted_at,
        mock_deadline=mock_deadline,
        draft_saved_at=draft_saved_at,
        updated_at=updated_at,
        elapsed_seconds=elapsed_seconds,
        answers=answers,
    )


# ---------------------------------------------------------------------------
# Test: AnswerSheet JSON round-trip
# ---------------------------------------------------------------------------


@given(sheet=_valid_answer_sheet())
@settings(max_examples=200, deadline=500)
def test_answer_sheet_json_round_trip(sheet: AnswerSheet) -> None:
    """Any valid AnswerSheet survives JSON round-trip with field equality.

    **Validates: Requirements 13.1, 13.3**

    Dumps the AnswerSheet to a JSON-compatible dict, re-validates from that
    dict, and asserts the two JSON representations are identical.
    """
    json_repr = sheet.model_dump(mode="json")
    sheet_restored = AnswerSheet.model_validate(json_repr)
    json_repr_restored = sheet_restored.model_dump(mode="json")
    assert json_repr_restored == json_repr
