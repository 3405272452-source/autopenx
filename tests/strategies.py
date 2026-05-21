"""Central Hypothesis strategy library for CET-4 Study App domain tests.

This module is deliberately thin and **domain-pure**: it imports only from the
Python standard library, ``hypothesis``, ``pydantic``, and
``cet4_app.domain.*``. It MUST NOT import PySide6, httpx, SQLAlchemy, or any
other infrastructure dependency — that invariant is enforced by
``import-linter`` in task 1.2 and protects the hypothesis test suite from
needing a Qt / HTTP stack during CI.

The strategies below are the shared source of truth for property-based
tests under ``tests/domain/`` (Question field-level validation, type
invariants, JSON round-trip, etc.). Each strategy is named after what it
produces so tests can declaratively compose them.

Exports:

* :func:`valid_option`          — a single well-formed option string
* :func:`valid_prompt`          — a well-formed prompt body
* :func:`valid_tags`            — a well-formed tags list
* :func:`valid_score_decimal`   — a ``Decimal`` score ∈ [0, 100] w/ 2 places
* :func:`valid_audio_range`     — a well-formed ``AudioRange`` payload dict
* :func:`valid_question_strategy`           — a fully-valid ``Question`` payload
* :func:`invalid_question_payload_strategy` — a payload that violates exactly
  one intrinsic field-level rule (length bound, enum membership, list
  cardinality, score range, ``correct_letter`` literal)

Note on invalid payloads: the strategy intentionally restricts itself to
mutations that produce *field-level* Pydantic errors — i.e. errors whose
``loc`` is a non-empty tuple pointing at the offending field or list
element. Type-specific ``model_validator`` errors (cross-field rules) are
validated by task 3.3 (``test_question_type_invariants``); cross-model
Paper invariants (banked_cloze membership, long-matching paragraph keys)
are validated at Paper level by task 3.1's model_validator. This split
keeps each property test focused on a single layer of the validation
stack.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from hypothesis import strategies as st

from cet4_app.domain.enums import QuestionType, SectionName


__all__ = [
    "valid_option",
    "valid_prompt",
    "valid_tags",
    "valid_score_decimal",
    "valid_audio_range",
    "valid_question_strategy",
    "invalid_question_payload_strategy",
]


# ---------------------------------------------------------------------------
# Internal lookup tables (mirrors of constants in ``domain.models.question``).
# Duplicated here rather than imported so the strategy module stays
# self-contained and does not depend on private names.
# ---------------------------------------------------------------------------

_TYPE_TO_SECTION: dict[QuestionType, SectionName] = {
    QuestionType.writing: SectionName.writing,
    QuestionType.listening_news: SectionName.listening,
    QuestionType.listening_conversation: SectionName.listening,
    QuestionType.listening_passage: SectionName.listening,
    QuestionType.reading_banked_cloze: SectionName.reading,
    QuestionType.reading_long_matching: SectionName.reading,
    QuestionType.reading_careful_choice: SectionName.reading,
    QuestionType.translation: SectionName.translation,
}

_CHOICE_TYPES: tuple[QuestionType, ...] = (
    QuestionType.listening_news,
    QuestionType.listening_conversation,
    QuestionType.listening_passage,
    QuestionType.reading_careful_choice,
)

_LISTENING_TYPES: tuple[QuestionType, ...] = (
    QuestionType.listening_news,
    QuestionType.listening_conversation,
    QuestionType.listening_passage,
)

_SUBJECTIVE_TYPES: tuple[QuestionType, ...] = (
    QuestionType.writing,
    QuestionType.translation,
)

# Paragraph identifiers A..O (matches Requirement 3.4).
_PARAGRAPH_ALPHABET: tuple[str, ...] = tuple(chr(ord("A") + i) for i in range(15))

# Restricted alphabet for generated strings. Printable ASCII keeps generated
# payloads trivially JSON-safe and trivially human-readable in failure output
# while still exercising the full range of length bounds we want to test.
_ASCII_PRINTABLE = st.characters(
    min_codepoint=0x21,  # skip space to guarantee ``strip()`` is a no-op
    max_codepoint=0x7E,
    blacklist_characters='"\\',  # avoid JSON-escape edge cases
)


# ---------------------------------------------------------------------------
# Leaf strategies — reusable across question types and tests.
# ---------------------------------------------------------------------------


def valid_option() -> st.SearchStrategy[str]:
    """A well-formed option string (1..512 chars, Requirement 3.5).

    Returned strings are printable ASCII of length ``1..64`` — well within
    the 512-char upper bound and small enough to keep hypothesis shrinking
    fast.
    """

    return st.text(alphabet=_ASCII_PRINTABLE, min_size=1, max_size=64)


def valid_prompt() -> st.SearchStrategy[str]:
    """A well-formed ``prompt`` string (1..4096 chars, Requirement 3.1)."""

    return st.text(min_size=1, max_size=256)


def valid_tags() -> st.SearchStrategy[list[str]]:
    """A well-formed ``tags`` list (0..20 elements, each 1..32 chars).

    Implements Requirements 3.1 and 3.8. Uses ``unique=True`` to avoid
    coincidental duplicates — the model does not enforce uniqueness on
    tags, but unique payloads remain more readable in failure output.
    """

    return st.lists(
        st.text(alphabet=_ASCII_PRINTABLE, min_size=1, max_size=16),
        min_size=0,
        max_size=5,
        unique=True,
    )


def valid_score_decimal() -> st.SearchStrategy[Decimal]:
    """A ``Decimal`` score in ``[0, 100]`` with exactly 2 decimal places.

    Mirrors ``condecimal(ge=0, le=100, decimal_places=2)`` from Requirement
    3.1 / 3.7.
    """

    return st.decimals(
        min_value=Decimal("0"),
        max_value=Decimal("100"),
        places=2,
        allow_nan=False,
        allow_infinity=False,
    )


@st.composite
def valid_audio_range(draw: st.DrawFn) -> dict[str, float]:
    """A well-formed :class:`AudioRange` payload as a raw ``dict``.

    Guarantees ``end_s > start_s`` by construction (Requirement 5.2 / 5.4):
    draws ``start_s`` and a strictly positive ``gap`` of at least 1.0
    seconds to avoid float-precision corner cases that could collapse
    ``start + gap`` back to ``start``.
    """

    start_s = draw(
        st.floats(
            min_value=0.0,
            max_value=1000.0,
            allow_nan=False,
            allow_infinity=False,
        )
    )
    gap = draw(
        st.floats(
            min_value=1.0,
            max_value=600.0,
            allow_nan=False,
            allow_infinity=False,
        )
    )
    return {"start_s": start_s, "end_s": start_s + gap}


# ---------------------------------------------------------------------------
# Top-level valid Question payload strategy.
# ---------------------------------------------------------------------------


@st.composite
def valid_question_strategy(draw: st.DrawFn) -> dict[str, Any]:
    """Produce a fully-valid :class:`Question` payload as a ``dict``.

    The returned mapping is guaranteed to pass
    ``Question.model_validate(payload)`` for *any* ``QuestionType``:

    * Field-level constraints from Requirement 3.1–3.8 (lengths, enums,
      ranges, list cardinalities) are respected.
    * Type-specific invariants from
      ``Question.model_validator(mode="after")`` are respected:

      - ``reading_careful_choice`` / ``listening_*`` → exactly 4 distinct
        options + a valid ``correct_letter`` ∈ {A,B,C,D}.
      - ``reading_banked_cloze`` → ``blank_index`` ∈ ``[1, 10]``.
      - ``reading_long_matching`` → ``paragraph_key`` is ``None`` or a
        single uppercase letter in ``A..O``.
      - ``writing`` / ``translation`` → ``options == []``,
        ``reference_answer`` and ``explanation`` both non-empty.

    Paper-level cross-question invariants (Banked_Cloze shared candidate
    membership, Long_Matching paragraph-key membership, exactly 15 shared
    candidates) are intentionally *not* enforced here — they belong at the
    Paper level and are exercised by separate strategies.
    """

    question_type: QuestionType = draw(st.sampled_from(list(QuestionType)))
    section = _TYPE_TO_SECTION[question_type]

    payload: dict[str, Any] = {
        "id": draw(st.text(alphabet=_ASCII_PRINTABLE, min_size=1, max_size=64)),
        "paper_id": draw(st.text(alphabet=_ASCII_PRINTABLE, min_size=1, max_size=32)),
        "section": section.value,
        "sub_section": draw(st.text(alphabet=_ASCII_PRINTABLE, min_size=0, max_size=32)),
        "question_type": question_type.value,
        "prompt": draw(valid_prompt()),
        "options": [],
        "correct_letter": None,
        "reference_answer": "",
        "explanation": "",
        "score": draw(valid_score_decimal()),
        "tags": draw(valid_tags()),
        "audio_range": None,
        "blank_index": None,
        "paragraph_key": None,
        "min_words": None,
        "max_words": None,
    }

    if question_type in _CHOICE_TYPES:
        # Exactly 4 pairwise-distinct options + a letter in A..D.
        payload["options"] = draw(
            st.lists(valid_option(), min_size=4, max_size=4, unique=True)
        )
        payload["correct_letter"] = draw(st.sampled_from(["A", "B", "C", "D"]))
        # Listening sub-types may carry an audio_range; it's optional per
        # Requirement 5.5 fallback to group start.
        if question_type in _LISTENING_TYPES:
            payload["audio_range"] = draw(st.one_of(st.none(), valid_audio_range()))

    elif question_type == QuestionType.reading_banked_cloze:
        payload["blank_index"] = draw(st.integers(min_value=1, max_value=10))
        # reference_answer may be empty (Paper-level cross-check is separate)
        # or any short word — both pass Question intrinsic validation.
        payload["reference_answer"] = draw(
            st.text(alphabet=_ASCII_PRINTABLE, min_size=0, max_size=32)
        )

    elif question_type == QuestionType.reading_long_matching:
        payload["paragraph_key"] = draw(
            st.one_of(st.none(), st.sampled_from(_PARAGRAPH_ALPHABET))
        )

    elif question_type in _SUBJECTIVE_TYPES:
        # writing / translation require non-empty reference_answer & explanation
        # and an empty options list (enforced by model_validator).
        payload["reference_answer"] = draw(st.text(min_size=1, max_size=256))
        payload["explanation"] = draw(st.text(min_size=1, max_size=256))
        payload["min_words"] = draw(
            st.one_of(st.none(), st.integers(min_value=1, max_value=500))
        )
        payload["max_words"] = draw(
            st.one_of(st.none(), st.integers(min_value=500, max_value=2000))
        )

    return payload


# ---------------------------------------------------------------------------
# Invalid payload strategy.
#
# Each branch produces a dict that violates *exactly one* field-level rule,
# yielding a Pydantic ``ValidationError`` with a non-empty ``loc`` tuple
# pointing at the offending field or list element. All mutations are kept
# small (short invalid strings, single over-the-limit element) so the
# resulting error messages stay bounded well under 200 chars.
# ---------------------------------------------------------------------------


_INVALID_MUTATIONS: tuple[str, ...] = (
    # --- id bounds ------------------------------------------------------
    "id_empty",
    "id_too_long",
    # --- paper_id bounds -----------------------------------------------
    "paper_id_empty",
    "paper_id_too_long",
    # --- enum membership ------------------------------------------------
    "section_invalid_enum",
    "question_type_invalid_enum",
    # --- sub_section upper bound ---------------------------------------
    "sub_section_too_long",
    # --- prompt bounds --------------------------------------------------
    "prompt_empty",
    "prompt_too_long",
    # --- options list & element bounds (tag/option cardinality) --------
    "options_list_too_long",
    "option_element_empty",
    "option_element_too_long",
    # --- reference_answer / explanation length bounds ------------------
    "reference_answer_too_long",
    "explanation_too_long",
    # --- score range ---------------------------------------------------
    "score_below_zero",
    "score_above_hundred",
    # --- tags cardinality & element bounds -----------------------------
    "tags_list_too_long",
    "tag_element_empty",
    "tag_element_too_long",
    # --- correct_letter Literal -----------------------------------------
    "correct_letter_invalid_literal",
)


def _apply_mutation(payload: dict[str, Any], mutation: str) -> dict[str, Any]:
    """Return a copy of ``payload`` with exactly one field-level violation.

    This is the single place that encodes the mapping from mutation name
    to concrete invalid value. Each branch is crafted so that the first
    failing Pydantic validation step is a *field-level* one (min_length /
    max_length / enum / Literal / ge / le), leaving the model-validator
    untouched — that way ``errors()[0]["loc"]`` is guaranteed to be a
    non-empty tuple.
    """

    p = dict(payload)

    if mutation == "id_empty":
        p["id"] = ""
    elif mutation == "id_too_long":
        # 1 char over the 128-char upper bound.
        p["id"] = "x" * 129
    elif mutation == "paper_id_empty":
        p["paper_id"] = ""
    elif mutation == "paper_id_too_long":
        p["paper_id"] = "x" * 65
    elif mutation == "section_invalid_enum":
        p["section"] = "not_a_valid_section"
    elif mutation == "question_type_invalid_enum":
        p["question_type"] = "not_a_valid_type"
    elif mutation == "sub_section_too_long":
        p["sub_section"] = "x" * 65
    elif mutation == "prompt_empty":
        p["prompt"] = ""
    elif mutation == "prompt_too_long":
        p["prompt"] = "x" * 4097
    elif mutation == "options_list_too_long":
        # 11 items > max_length=10, regardless of question_type.
        p["options"] = [f"opt-{i}" for i in range(11)]
    elif mutation == "option_element_empty":
        # Insert an empty string as the first option (min_length=1 violation).
        existing = list(p.get("options") or [])
        p["options"] = [""] + existing[:3]
    elif mutation == "option_element_too_long":
        # 513-char string > max_length=512 on a single option element.
        existing = list(p.get("options") or [])
        p["options"] = ["x" * 513] + existing[:3]
    elif mutation == "reference_answer_too_long":
        p["reference_answer"] = "x" * 8193
    elif mutation == "explanation_too_long":
        p["explanation"] = "x" * 4097
    elif mutation == "score_below_zero":
        p["score"] = Decimal("-0.01")
    elif mutation == "score_above_hundred":
        p["score"] = Decimal("100.01")
    elif mutation == "tags_list_too_long":
        # 21 unique tags > max_length=20.
        p["tags"] = [f"tag{i:02d}" for i in range(21)]
    elif mutation == "tag_element_empty":
        p["tags"] = [""]
    elif mutation == "tag_element_too_long":
        p["tags"] = ["x" * 33]
    elif mutation == "correct_letter_invalid_literal":
        # "E" is not in Literal["A","B","C","D"]; triggers a field-level
        # Literal violation with loc=("correct_letter",).
        p["correct_letter"] = "E"
    else:  # pragma: no cover - defensive: unknown mutation name
        raise AssertionError(f"unknown invalid mutation: {mutation!r}")

    return p


@st.composite
def invalid_question_payload_strategy(draw: st.DrawFn) -> dict[str, Any]:
    """Produce a :class:`Question` payload that fails exactly one field-level rule.

    The returned dict is guaranteed to raise ``pydantic.ValidationError``
    when passed to ``Question.model_validate`` and to produce at least one
    error whose ``loc`` is a non-empty tuple. The mutation is chosen
    uniformly from :data:`_INVALID_MUTATIONS`.
    """

    base = draw(valid_question_strategy())
    mutation = draw(st.sampled_from(_INVALID_MUTATIONS))
    return _apply_mutation(base, mutation)
