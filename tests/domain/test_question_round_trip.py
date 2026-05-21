"""Property test: Question/Paper JSON round-trip (task 3.4).

**Property 6: 所有核心模型满足 JSON Round_Trip（Question/Paper 部分）**
**Validates: Requirements 2.12, 13.1, 13.2, 13.7**

This module verifies that:

1. Any valid ``Question`` survives a JSON serialization → deserialization
   round trip with field-level equality preserved.
2. Any valid ``Paper`` (containing banked_cloze + long_matching +
   careful_reading + writing sections) survives the same round trip.

The round-trip assertion is:

    Question.model_validate(q.model_dump(mode="json")).model_dump(mode="json")
        == q.model_dump(mode="json")

This guarantees that Pydantic's JSON serializer and validator are
symmetric — no data is lost, no fields drift, and no type coercions
introduce inequality (Requirement 13.2).

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from decimal import Decimal
from string import ascii_letters, digits

from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import (
    AudioStatus,
    PaperStatus,
    QuestionType,
    SectionName,
)
from cet4_app.domain.models.question import (
    Paper,
    Question,
    Section,
    SubSection,
)
from tests.strategies import valid_question_strategy


# ---------------------------------------------------------------------------
# Test 1: Question JSON round-trip
# ---------------------------------------------------------------------------


@given(payload=valid_question_strategy())
@settings(max_examples=200, deadline=500)
def test_question_json_round_trip(payload: dict) -> None:
    """Any valid Question survives JSON round-trip with field equality.

    **Validates: Requirements 2.12, 13.1, 13.2**

    Constructs a Question from a valid payload, dumps it to JSON-compatible
    dict, re-validates from that dict, and asserts the two JSON representations
    are identical.
    """
    q = Question.model_validate(payload)
    json_repr = q.model_dump(mode="json")
    q_restored = Question.model_validate(json_repr)
    json_repr_restored = q_restored.model_dump(mode="json")
    assert json_repr_restored == json_repr


# ---------------------------------------------------------------------------
# Inline composite strategy for a minimal valid Paper
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)
_non_empty_text = st.text(min_size=1, max_size=128)
_option_text = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=48)
_word_text = st.text(alphabet=ascii_letters, min_size=1, max_size=20)
_score = st.decimals(
    min_value=Decimal("0.00"),
    max_value=Decimal("100.00"),
    places=2,
    allow_nan=False,
    allow_infinity=False,
)
_PARAGRAPH_LETTERS: tuple[str, ...] = tuple(chr(ord("A") + i) for i in range(15))


@st.composite
def _valid_paper_strategy(draw: st.DrawFn) -> Paper:
    """Build a minimal valid Paper with multiple section types.

    Includes:
    - A banked_cloze sub-section with 2 questions (shared 15 words)
    - A long_matching sub-section with 2 questions (A..E paragraphs)
    - A careful_reading sub-section with 2 questions (4 options each)
    - A writing sub-section with 1 question

    This exercises the Paper-level cross-question validators and ensures
    the full Paper structure round-trips correctly.
    """
    paper_id = draw(_short_ident)

    # --- shared_banked_words: exactly 15 distinct words ----------------
    shared_banked_words = draw(
        st.lists(_word_text, min_size=15, max_size=15, unique=True)
    )

    # --- long_reading_paragraphs: A..E (5 paragraphs) -----------------
    paragraph_keys = list(_PARAGRAPH_LETTERS[:5])
    long_reading_paragraphs = {
        k: draw(_non_empty_text) for k in paragraph_keys
    }

    # --- Banked Cloze questions ----------------------------------------
    banked_questions = []
    for i in range(1, 3):  # 2 questions
        ref_answer = draw(st.sampled_from([""] + shared_banked_words[:5]))
        banked_questions.append(
            Question(
                id=f"{paper_id}-banked-{i:02d}",
                paper_id=paper_id,
                section=SectionName.reading,
                sub_section="Banked_Cloze",
                question_type=QuestionType.reading_banked_cloze,
                prompt=draw(_non_empty_text),
                options=[],
                reference_answer=ref_answer,
                explanation="",
                score=draw(_score),
                blank_index=i,
            )
        )

    # --- Long Matching questions ---------------------------------------
    matching_questions = []
    for i in range(1, 3):  # 2 questions
        matching_questions.append(
            Question(
                id=f"{paper_id}-lm-{i:02d}",
                paper_id=paper_id,
                section=SectionName.reading,
                sub_section="Long_Reading",
                question_type=QuestionType.reading_long_matching,
                prompt=draw(_non_empty_text),
                options=[],
                reference_answer="",
                explanation="",
                score=draw(_score),
                paragraph_key=draw(st.sampled_from(paragraph_keys)),
            )
        )

    # --- Careful Reading questions -------------------------------------
    careful_questions = []
    for i in range(1, 3):  # 2 questions
        careful_questions.append(
            Question(
                id=f"{paper_id}-careful-{i:02d}",
                paper_id=paper_id,
                section=SectionName.reading,
                sub_section="Careful_Reading",
                question_type=QuestionType.reading_careful_choice,
                prompt=draw(_non_empty_text),
                options=draw(
                    st.lists(_option_text, min_size=4, max_size=4, unique=True)
                ),
                correct_letter=draw(st.sampled_from(["A", "B", "C", "D"])),
                reference_answer="",
                explanation="",
                score=draw(_score),
            )
        )

    # --- Writing question ----------------------------------------------
    writing_question = Question(
        id=f"{paper_id}-writing-01",
        paper_id=paper_id,
        section=SectionName.writing,
        sub_section="",
        question_type=QuestionType.writing,
        prompt=draw(_non_empty_text),
        options=[],
        reference_answer=draw(_non_empty_text),
        explanation=draw(_non_empty_text),
        score=draw(_score),
        min_words=draw(st.one_of(st.none(), st.integers(min_value=1, max_value=300))),
        max_words=draw(st.one_of(st.none(), st.integers(min_value=300, max_value=1000))),
    )

    # --- Assemble Paper ------------------------------------------------
    reading_section = Section(
        name=SectionName.reading,
        sub_sections=[
            SubSection(name="Banked_Cloze", questions=banked_questions),
            SubSection(name="Long_Reading", questions=matching_questions),
            SubSection(name="Careful_Reading", questions=careful_questions),
        ],
    )
    writing_section = Section(
        name=SectionName.writing,
        sub_sections=[
            SubSection(name="Writing", questions=[writing_question]),
        ],
    )

    paper = Paper(
        paper_id=paper_id,
        paper_set_id=draw(_short_ident),
        exam_period=draw(st.sampled_from(["2023-12", "2024-06", "2024-12", "2025-06"])),
        set_index=draw(st.integers(min_value=1, max_value=3)),
        audio_status=draw(st.sampled_from(list(AudioStatus))),
        status=PaperStatus.ok,
        sections=[reading_section, writing_section],
        shared_banked_words=shared_banked_words,
        long_reading_paragraphs=long_reading_paragraphs,
    )
    return paper


# ---------------------------------------------------------------------------
# Test 2: Paper JSON round-trip
# ---------------------------------------------------------------------------


@given(paper=_valid_paper_strategy())
@settings(max_examples=200, deadline=500)
def test_paper_json_round_trip(paper: Paper) -> None:
    """Any valid Paper survives JSON round-trip with field equality.

    **Validates: Requirements 2.12, 13.1, 13.2, 13.7**

    Dumps the Paper to a JSON-compatible dict, re-validates from that dict,
    and asserts the two JSON representations are identical.
    """
    json_repr = paper.model_dump(mode="json")
    paper_restored = Paper.model_validate(json_repr)
    json_repr_restored = paper_restored.model_dump(mode="json")
    assert json_repr_restored == json_repr
