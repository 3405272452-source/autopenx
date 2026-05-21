"""Property test: Question type-specific invariants (task 3.3).

Property 5: Question 按 question_type 满足题型专属不变量.
Validates: Requirements 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 3.3, 3.4, 3.5, 3.6.

This module exercises the per-``question_type`` invariants enforced by
:class:`cet4_app.domain.models.question.Question` (via its
``model_validator(mode="after")``) and, for ``reading_banked_cloze`` and
``reading_long_matching``, their cross-references back to
``Paper.shared_banked_words`` and ``Paper.long_reading_paragraphs``.

For each of the eight CET-4 ``QuestionType`` values we provide:

* A **positive** hypothesis strategy that constructs a valid question of that
  type and asserts the type-specific invariants hold post-validation.
* A **negative** hypothesis-driven test per invariant group that builds a
  payload violating *exactly* the type-specific rule and asserts
  :class:`pydantic.ValidationError` is raised with a ``loc`` / ``msg`` that
  identifies the violated invariant.

The positive strategies for ``reading_banked_cloze`` and
``reading_long_matching`` wrap the :class:`Question` inside a valid
:class:`Paper` in order to exercise the cross-model checks
(``shared_banked_words`` membership, ``long_reading_paragraphs`` key
presence).

Design notes:

* Helpers are inlined on purpose. Task 3.2 plans to add a shared
  ``tests/strategies.py`` but is scheduled in the same wave; inlining keeps
  this module self-contained and insulates it from ordering issues during
  parallel task execution.
* ``@settings(max_examples=50, deadline=None)`` is applied per test per the
  task brief.
* Domain-layer purity is preserved: the module imports only ``pydantic``,
  ``hypothesis``, and ``cet4_app.domain`` — no Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from decimal import Decimal
from string import ascii_letters, digits

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from cet4_app.domain.enums import (
    AudioStatus,
    PaperStatus,
    QuestionType,
    SectionName,
)
from cet4_app.domain.models.question import (
    AudioRange,
    Paper,
    Question,
    Section,
    SubSection,
)


# ---------------------------------------------------------------------------
# Inline helper strategies (kept local — see module docstring).
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_PARAGRAPH_LETTERS: tuple[str, ...] = tuple(chr(ord("A") + i) for i in range(15))

_LISTENING_TYPES: frozenset[QuestionType] = frozenset(
    {
        QuestionType.listening_news,
        QuestionType.listening_conversation,
        QuestionType.listening_passage,
    }
)

_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=32)
_sub_section_text = st.text(alphabet=_IDENT_ALPHABET, min_size=0, max_size=32)
_non_empty_text = st.text(min_size=1, max_size=200)
_option_text = st.text(min_size=1, max_size=64)
_word_text = st.text(alphabet=ascii_letters, min_size=1, max_size=32)
_score = st.decimals(
    min_value=Decimal("0.00"),
    max_value=Decimal("100.00"),
    places=2,
    allow_nan=False,
    allow_infinity=False,
)
_letter = st.sampled_from(["A", "B", "C", "D"])


def _four_distinct_options():
    return st.lists(_option_text, min_size=4, max_size=4, unique=True)


def _valid_audio_range_strategy():
    """Always yields an AudioRange with ``end_s > start_s``."""

    return st.builds(
        AudioRange,
        start_s=st.floats(
            min_value=0.0,
            max_value=1000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
        end_s=st.floats(
            min_value=1000.5,
            max_value=2000.0,
            allow_nan=False,
            allow_infinity=False,
        ),
    )


# ---------------------------------------------------------------------------
# Positive strategies — one composite per invariant shape.
# ---------------------------------------------------------------------------


@st.composite
def _valid_choice_question(
    draw: st.DrawFn,
    question_type: QuestionType,
    section: SectionName,
) -> Question:
    """Valid choice-style question: 4 distinct options + correct_letter."""

    audio_range_val = (
        draw(st.one_of(st.none(), _valid_audio_range_strategy()))
        if question_type in _LISTENING_TYPES
        else None
    )
    return Question(
        id=draw(_short_ident),
        paper_id=draw(_short_ident),
        section=section,
        sub_section=draw(_sub_section_text),
        question_type=question_type,
        prompt=draw(_non_empty_text),
        options=draw(_four_distinct_options()),
        correct_letter=draw(_letter),
        reference_answer="",
        explanation="",
        score=draw(_score),
        audio_range=audio_range_val,
    )


@st.composite
def _valid_subjective_question(
    draw: st.DrawFn,
    question_type: QuestionType,
    section: SectionName,
) -> Question:
    """Valid writing/translation question: empty options + non-empty text."""

    return Question(
        id=draw(_short_ident),
        paper_id=draw(_short_ident),
        section=section,
        question_type=question_type,
        prompt=draw(_non_empty_text),
        options=[],
        reference_answer=draw(_non_empty_text),
        explanation=draw(_non_empty_text),
        score=draw(_score),
    )


@st.composite
def _valid_paper_with_banked_cloze(
    draw: st.DrawFn,
) -> tuple[Paper, Question]:
    """A Paper containing one valid ``reading_banked_cloze`` question.

    Exercises the cross-check that ``reference_answer`` is either empty or
    a member of ``Paper.shared_banked_words``.
    """

    shared = draw(st.lists(_word_text, min_size=15, max_size=15, unique=True))
    # Either cannot-grade (empty) or a member of the shared bank.
    reference = draw(st.one_of(st.just(""), st.sampled_from(shared)))
    blank_index = draw(st.integers(min_value=1, max_value=10))
    question = Question(
        id=draw(_short_ident),
        paper_id="p-banked",
        section=SectionName.reading,
        sub_section="Banked_Cloze",
        question_type=QuestionType.reading_banked_cloze,
        prompt=draw(_non_empty_text),
        options=[],
        reference_answer=reference,
        explanation="",
        score=draw(_score),
        blank_index=blank_index,
    )
    paper = Paper(
        paper_id="p-banked",
        paper_set_id="ps-banked",
        exam_period="2024-12",
        set_index=1,
        audio_status=AudioStatus.available,
        status=PaperStatus.ok,
        sections=[
            Section(
                name=SectionName.reading,
                sub_sections=[
                    SubSection(name="Banked_Cloze", questions=[question])
                ],
            )
        ],
        shared_banked_words=shared,
    )
    return paper, question


@st.composite
def _valid_paper_with_long_matching(
    draw: st.DrawFn,
) -> tuple[Paper, Question]:
    """A Paper containing one valid ``reading_long_matching`` question.

    Exercises the cross-check that ``paragraph_key`` appears in
    ``Paper.long_reading_paragraphs``.
    """

    n_paragraphs = draw(st.integers(min_value=1, max_value=15))
    paragraph_keys = list(_PARAGRAPH_LETTERS[:n_paragraphs])
    paragraphs = {k: f"paragraph body {k}" for k in paragraph_keys}
    paragraph_key = draw(st.sampled_from(paragraph_keys))
    question = Question(
        id=draw(_short_ident),
        paper_id="p-lm",
        section=SectionName.reading,
        sub_section="Long_Reading",
        question_type=QuestionType.reading_long_matching,
        prompt=draw(_non_empty_text),
        options=[],
        reference_answer="",
        explanation="",
        score=draw(_score),
        paragraph_key=paragraph_key,
    )
    paper = Paper(
        paper_id="p-lm",
        paper_set_id="ps-lm",
        exam_period="2024-12",
        set_index=1,
        audio_status=AudioStatus.available,
        status=PaperStatus.ok,
        sections=[
            Section(
                name=SectionName.reading,
                sub_sections=[
                    SubSection(name="Long_Reading", questions=[question])
                ],
            )
        ],
        long_reading_paragraphs=paragraphs,
    )
    return paper, question


# ---------------------------------------------------------------------------
# Positive tests — one per QuestionType enum value.
# ---------------------------------------------------------------------------


@given(q=_valid_subjective_question(QuestionType.writing, SectionName.writing))
@settings(max_examples=50, deadline=None)
def test_writing_invariants_hold(q: Question) -> None:
    """Validates: Requirements 2.7, 3.6."""

    assert q.question_type == QuestionType.writing
    assert q.options == []
    assert len(q.reference_answer) >= 1
    assert len(q.explanation) >= 1


@given(
    q=_valid_subjective_question(
        QuestionType.translation, SectionName.translation
    )
)
@settings(max_examples=50, deadline=None)
def test_translation_invariants_hold(q: Question) -> None:
    """Validates: Requirements 2.8, 3.6."""

    assert q.question_type == QuestionType.translation
    assert q.options == []
    assert len(q.reference_answer) >= 1
    assert len(q.explanation) >= 1


@given(
    q=_valid_choice_question(
        QuestionType.listening_news, SectionName.listening
    )
)
@settings(max_examples=50, deadline=None)
def test_listening_news_invariants_hold(q: Question) -> None:
    """Validates: Requirements 2.6, 3.5."""

    assert q.question_type == QuestionType.listening_news
    assert len(q.options) == 4
    assert len(set(q.options)) == 4
    assert q.correct_letter in {"A", "B", "C", "D"}
    if q.audio_range is not None:
        assert q.audio_range.start_s < q.audio_range.end_s


@given(
    q=_valid_choice_question(
        QuestionType.listening_conversation, SectionName.listening
    )
)
@settings(max_examples=50, deadline=None)
def test_listening_conversation_invariants_hold(q: Question) -> None:
    """Validates: Requirements 2.6, 3.5."""

    assert q.question_type == QuestionType.listening_conversation
    assert len(q.options) == 4
    assert len(set(q.options)) == 4
    assert q.correct_letter in {"A", "B", "C", "D"}
    if q.audio_range is not None:
        assert q.audio_range.start_s < q.audio_range.end_s


@given(
    q=_valid_choice_question(
        QuestionType.listening_passage, SectionName.listening
    )
)
@settings(max_examples=50, deadline=None)
def test_listening_passage_invariants_hold(q: Question) -> None:
    """Validates: Requirements 2.6, 3.5."""

    assert q.question_type == QuestionType.listening_passage
    assert len(q.options) == 4
    assert len(set(q.options)) == 4
    assert q.correct_letter in {"A", "B", "C", "D"}
    if q.audio_range is not None:
        assert q.audio_range.start_s < q.audio_range.end_s


@given(
    q=_valid_choice_question(
        QuestionType.reading_careful_choice, SectionName.reading
    )
)
@settings(max_examples=50, deadline=None)
def test_reading_careful_choice_invariants_hold(q: Question) -> None:
    """Validates: Requirements 2.5, 3.5."""

    assert q.question_type == QuestionType.reading_careful_choice
    assert len(q.options) == 4
    assert len(set(q.options)) == 4
    assert q.correct_letter in {"A", "B", "C", "D"}


@given(bundle=_valid_paper_with_banked_cloze())
@settings(max_examples=50, deadline=None)
def test_reading_banked_cloze_invariants_hold(
    bundle: tuple[Paper, Question],
) -> None:
    """Validates: Requirements 2.3, 3.3."""

    paper, q = bundle
    assert q.question_type == QuestionType.reading_banked_cloze
    assert q.blank_index is not None
    assert 1 <= q.blank_index <= 10
    # The shared bank must remain exactly 15 pairwise-distinct words.
    assert len(paper.shared_banked_words) == 15
    assert len(set(paper.shared_banked_words)) == 15
    # Reference answer is either empty (cannot-grade) or a bank member.
    assert (
        q.reference_answer == ""
        or q.reference_answer in paper.shared_banked_words
    )


@given(bundle=_valid_paper_with_long_matching())
@settings(max_examples=50, deadline=None)
def test_reading_long_matching_invariants_hold(
    bundle: tuple[Paper, Question],
) -> None:
    """Validates: Requirements 2.4, 3.4."""

    paper, q = bundle
    assert q.question_type == QuestionType.reading_long_matching
    assert q.paragraph_key is not None
    assert len(q.paragraph_key) == 1
    assert q.paragraph_key in _PARAGRAPH_LETTERS
    assert q.paragraph_key in paper.long_reading_paragraphs


# ---------------------------------------------------------------------------
# Negative tests — one per invariant group.
# ---------------------------------------------------------------------------


_CHOICE_TYPES: list[QuestionType] = [
    QuestionType.listening_news,
    QuestionType.listening_conversation,
    QuestionType.listening_passage,
    QuestionType.reading_careful_choice,
]

_CHOICE_SECTION: dict[QuestionType, SectionName] = {
    QuestionType.listening_news: SectionName.listening,
    QuestionType.listening_conversation: SectionName.listening,
    QuestionType.listening_passage: SectionName.listening,
    QuestionType.reading_careful_choice: SectionName.reading,
}


def _loc_str(err: dict) -> str:
    return "/".join(str(x) for x in err.get("loc", ()))


@given(
    question_type=st.sampled_from(_CHOICE_TYPES),
    n_options=st.sampled_from([0, 1, 2, 3, 5, 6, 7]),
)
@settings(max_examples=50, deadline=None)
def test_choice_style_rejects_wrong_option_count(
    question_type: QuestionType, n_options: int
) -> None:
    """Negative: choice-style requires exactly 4 distinct options.

    Validates: Requirements 2.5, 2.6, 3.5.
    """

    options = [f"opt-{i}" for i in range(n_options)]
    payload = {
        "id": "q-neg",
        "paper_id": "p-neg",
        "section": _CHOICE_SECTION[question_type].value,
        "question_type": question_type.value,
        "prompt": "prompt",
        "options": options,
        "correct_letter": "A",
        "score": "1.00",
    }
    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)
    errors = exc_info.value.errors()
    assert errors, "expected at least one validation error"
    assert any(
        "4 options" in e.get("msg", "")
        or "4 mutually distinct" in e.get("msg", "")
        or "options" in _loc_str(e)
        for e in errors
    )


@given(
    question_type=st.sampled_from(_CHOICE_TYPES),
    dup_index=st.integers(min_value=0, max_value=3),
)
@settings(max_examples=50, deadline=None)
def test_choice_style_rejects_duplicate_options(
    question_type: QuestionType, dup_index: int
) -> None:
    """Negative: choice-style requires 4 *distinct* options.

    Validates: Requirements 2.5, 2.6, 3.5.
    """

    options = ["opt-A", "opt-B", "opt-C", "opt-D"]
    options[dup_index] = options[(dup_index + 1) % 4]  # introduce a duplicate
    payload = {
        "id": "q-neg",
        "paper_id": "p-neg",
        "section": _CHOICE_SECTION[question_type].value,
        "question_type": question_type.value,
        "prompt": "prompt",
        "options": options,
        "correct_letter": "A",
        "score": "1.00",
    }
    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)
    errors = exc_info.value.errors()
    assert any(
        "mutually distinct" in e.get("msg", "")
        or "duplicates" in e.get("msg", "")
        for e in errors
    )


@given(
    blank_index=st.one_of(
        st.integers(max_value=0),
        st.integers(min_value=11, max_value=10_000),
    )
)
@settings(max_examples=50, deadline=None)
def test_banked_cloze_rejects_out_of_range_blank_index(
    blank_index: int,
) -> None:
    """Negative: ``blank_index`` must lie in 1..10.

    Validates: Requirements 2.3, 3.3.
    """

    payload = {
        "id": "q-neg",
        "paper_id": "p-neg",
        "section": "reading",
        "sub_section": "Banked_Cloze",
        "question_type": "reading_banked_cloze",
        "prompt": "fill the blank",
        "options": [],
        "reference_answer": "",
        "explanation": "",
        "score": "1.00",
        "blank_index": blank_index,
    }
    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)
    errors = exc_info.value.errors()
    assert any(
        "blank_index" in e.get("msg", "") or "blank_index" in _loc_str(e)
        for e in errors
    )


@given(
    bad_key=st.sampled_from(
        [
            "P",   # one past 'O'
            "Q",
            "R",
            "Z",
            "AA",  # too long
            "",    # empty string
            "a",   # lowercase
            "b",
            "o",
        ]
    )
)
@settings(max_examples=50, deadline=None)
def test_long_matching_rejects_bad_paragraph_key(bad_key: str) -> None:
    """Negative: ``paragraph_key`` must be a single uppercase letter A..O.

    Validates: Requirements 2.4, 3.4.
    """

    payload = {
        "id": "q-neg",
        "paper_id": "p-neg",
        "section": "reading",
        "sub_section": "Long_Reading",
        "question_type": "reading_long_matching",
        "prompt": "match",
        "options": [],
        "reference_answer": "",
        "explanation": "",
        "score": "1.00",
        "paragraph_key": bad_key,
    }
    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)
    errors = exc_info.value.errors()
    assert any(
        "paragraph_key" in e.get("msg", "") or "paragraph_key" in _loc_str(e)
        for e in errors
    )


@given(
    question_type=st.sampled_from(
        [QuestionType.writing, QuestionType.translation]
    ),
    bad_options=st.lists(_option_text, min_size=1, max_size=4),
)
@settings(max_examples=50, deadline=None)
def test_subjective_rejects_non_empty_options(
    question_type: QuestionType, bad_options: list[str]
) -> None:
    """Negative: writing / translation require ``options == []``.

    Validates: Requirements 2.7, 2.8, 3.6.
    """

    section = (
        SectionName.writing
        if question_type == QuestionType.writing
        else SectionName.translation
    )
    payload = {
        "id": "q-neg",
        "paper_id": "p-neg",
        "section": section.value,
        "question_type": question_type.value,
        "prompt": "prompt",
        "options": bad_options,
        "reference_answer": "reference",
        "explanation": "explanation",
        "score": "15.00",
    }
    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)
    errors = exc_info.value.errors()
    assert any(
        "options" in e.get("msg", "") or "options" in _loc_str(e)
        for e in errors
    )


@given(
    question_type=st.sampled_from(
        [QuestionType.writing, QuestionType.translation]
    ),
    drop_field=st.sampled_from(["reference_answer", "explanation"]),
)
@settings(max_examples=50, deadline=None)
def test_subjective_rejects_empty_reference_or_explanation(
    question_type: QuestionType, drop_field: str
) -> None:
    """Negative: subjective questions need non-empty ref + explanation.

    Validates: Requirements 2.7, 2.8, 3.6.
    """

    section = (
        SectionName.writing
        if question_type == QuestionType.writing
        else SectionName.translation
    )
    payload = {
        "id": "q-neg",
        "paper_id": "p-neg",
        "section": section.value,
        "question_type": question_type.value,
        "prompt": "prompt",
        "options": [],
        "reference_answer": "reference",
        "explanation": "explanation",
        "score": "15.00",
    }
    payload[drop_field] = ""
    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)
    errors = exc_info.value.errors()
    assert any(
        "non-empty" in e.get("msg", "") and drop_field in e.get("msg", "")
        for e in errors
    )


@given(
    question_type=st.sampled_from(sorted(_LISTENING_TYPES, key=lambda t: t.value)),
    start=st.floats(
        min_value=1.0, max_value=100.0, allow_nan=False, allow_infinity=False
    ),
    end_delta=st.floats(
        min_value=-50.0, max_value=0.0, allow_nan=False, allow_infinity=False
    ),
)
@settings(max_examples=50, deadline=None)
def test_listening_rejects_non_monotonic_audio_range(
    question_type: QuestionType, start: float, end_delta: float
) -> None:
    """Negative: when ``audio_range`` is set, ``end_s > start_s`` is required.

    Validates: Requirements 2.6, 3.5.
    """

    end = start + end_delta  # end <= start; sometimes negative
    payload = {
        "id": "q-neg",
        "paper_id": "p-neg",
        "section": "listening",
        "question_type": question_type.value,
        "prompt": "prompt",
        "options": ["a", "b", "c", "d"],
        "correct_letter": "A",
        "score": "1.00",
        "audio_range": {"start_s": start, "end_s": end},
    }
    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)
    errors = exc_info.value.errors()
    assert any(
        "audio_range" in _loc_str(e)
        or "end_s" in e.get("msg", "")
        or "greater than or equal to 0" in e.get("msg", "")
        for e in errors
    )
