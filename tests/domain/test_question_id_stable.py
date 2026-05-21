"""Property tests for the stable question-id builder.

**Property 3: Question 题号生成是稳定的纯函数**

Validates: Requirements 2.9

Requirement 2.9 mandates that every Question minted by the PDF_Parser
carries a canonical, deterministic identifier of the form::

    {exam_period}-set{set_index}-{section}-{sub_section}-{seq:02d}

and that any repeat parse of the same PDF produces the identical set of
identifiers. This can only hold if :func:`build_question_id` is a pure
function of its arguments — no global state, no clock reads, no
randomness.

These tests assert that property directly:

1. Calling ``build_question_id`` with the same arguments repeatedly
   returns the exact same string (idempotent / pure).
2. The emitted string matches the documented format for every
   combination of arguments drawn from the valid input space.
3. Collecting identifiers produced from the *same* list of argument
   tuples into two independent ``set`` objects yields equal sets
   (set idempotence — the PDF-parse-twice scenario in Req 2.9).
4. Out-of-range ``set_index`` / ``index`` / empty ``exam_period`` are
   rejected with :class:`ValueError`, matching the builder's contract.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import SectionName
from cet4_app.domain.ids.question_id import build_question_id


@settings(max_examples=100, deadline=None)
@given(
    exam_period=st.text(min_size=1, max_size=16),
    set_index=st.integers(min_value=1, max_value=3),
    section=st.sampled_from(SectionName),
    sub_section=st.text(max_size=32),
    index=st.integers(min_value=1, max_value=99),
)
def test_build_question_id_is_pure(
    exam_period: str,
    set_index: int,
    section: SectionName,
    sub_section: str,
    index: int,
) -> None:
    """Same arguments ⇒ same string, and the string matches the format.

    This is the core purity property for Requirement 2.9. If this ever
    fails, question ids are non-deterministic and the PDF-parser
    reproducibility guarantee is broken.
    """

    first = build_question_id(exam_period, set_index, section, sub_section, index)
    second = build_question_id(exam_period, set_index, section, sub_section, index)

    # Idempotent: repeated calls return the same value.
    assert first == second

    # Format contract: exactly what design.md `Pass 6` documents.
    expected = (
        f"{exam_period}-set{set_index}-{section.value}-{sub_section}-{index:02d}"
    )
    assert first == expected


@settings(max_examples=50, deadline=None)
@given(
    args=st.lists(
        st.tuples(
            st.text(min_size=1, max_size=16),
            st.integers(min_value=1, max_value=3),
            st.sampled_from(SectionName),
            st.text(max_size=32),
            st.integers(min_value=1, max_value=99),
        ),
        min_size=0,
        max_size=30,
        unique=True,
    ),
)
def test_build_question_id_set_idempotent(
    args: list[tuple[str, int, SectionName, str, int]],
) -> None:
    """Set of ids produced twice from the same tuples must be equal.

    Models Requirement 2.9's "re-parsing the same PDF yields the same
    set of question ids": even if the parser re-emits tuples in a
    different order, the *set* of ids collapses to the identical set.
    """

    first_set = {build_question_id(*a) for a in args}
    second_set = {build_question_id(*a) for a in args}

    assert first_set == second_set


@settings(max_examples=50, deadline=None)
@given(set_index=st.integers().filter(lambda n: n < 1 or n > 3))
def test_build_question_id_rejects_out_of_range_set_index(set_index: int) -> None:
    """``set_index`` outside ``1..3`` must raise ``ValueError``."""

    with pytest.raises(ValueError):
        build_question_id(
            "2024-12",
            set_index,
            SectionName.reading,
            "careful",
            1,
        )


@settings(max_examples=50, deadline=None)
@given(index=st.integers().filter(lambda n: n < 1 or n > 99))
def test_build_question_id_rejects_out_of_range_index(index: int) -> None:
    """``index`` outside ``1..99`` must raise ``ValueError``."""

    with pytest.raises(ValueError):
        build_question_id(
            "2024-12",
            1,
            SectionName.reading,
            "careful",
            index,
        )


def test_build_question_id_rejects_empty_exam_period() -> None:
    """Empty ``exam_period`` must raise ``ValueError``."""

    with pytest.raises(ValueError):
        build_question_id("", 1, SectionName.reading, "careful", 1)
