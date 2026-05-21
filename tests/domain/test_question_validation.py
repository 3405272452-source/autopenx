"""Property tests for :class:`Question` field-level validation.

**Property 4: Question_Model 字段级校验接受合法、拒绝非法并报告字段路径**

Validates: Requirements 3.1, 3.2, 3.7, 3.8, 3.9, 13.9

These tests exercise the *intrinsic* field-level contract of
:class:`cet4_app.domain.models.question.Question` — the rules from
Requirements 3.1–3.8 and 3.9 that every single Question payload must
satisfy regardless of the surrounding Paper.

Two complementary properties are asserted:

1. **Acceptance** — any payload drawn from :func:`valid_question_strategy`
   must round-trip cleanly: ``Question.model_validate`` succeeds and
   the serialised JSON form survives ``model_dump(mode="json") →
   model_validate`` (Requirement 13.9's structural purity claim applied
   at the Question level).

2. **Rejection with loc + bounded value summary** — any payload drawn
   from :func:`invalid_question_payload_strategy` must raise
   :class:`pydantic.ValidationError`, and *every* error the exception
   reports must carry a non-empty ``loc`` tuple (Requirement 3.9's
   "被拒字段名") and a bounded message string ≤ 200 characters
   (Requirement 3.9 / 13.9's "实际取值摘要 ≤ 200 字符").

Cross-model Paper invariants (Banked_Cloze shared candidate membership,
Long_Matching paragraph-key membership, exact 15-word shared candidate
list) are intentionally out of scope — they belong to Paper-level tests.
Type-specific structural rules (e.g. writing/translation requiring a
non-empty reference answer) are exercised by task 3.3.

The strategies live in :mod:`tests.strategies` and are used verbatim; if
a counter-example is found, the fix should either tighten the model
(if the property is correct) or loosen the strategy (if the property is
over-constrained). Both changes belong in separate commits.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from pydantic import ValidationError

from cet4_app.domain.models.question import Question
from tests.strategies import (
    invalid_question_payload_strategy,
    valid_question_strategy,
)


# ---------------------------------------------------------------------------
# Property 4a — acceptance + JSON round-trip on valid payloads.
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(payload=valid_question_strategy())
def test_valid_question_constructs_successfully(payload: dict[str, Any]) -> None:
    """A valid payload constructs a :class:`Question` and round-trips through JSON.

    This is the *acceptance* half of Property 4: for every payload
    satisfying the field-level and type-specific invariants documented
    in Requirements 3.1–3.8, ``Question.model_validate`` succeeds.

    Additionally, the JSON round-trip assertion guards against silent
    schema drift between Pydantic serialisation and validation — a
    regression here would break Requirement 13 (往返一致性) at the
    Question level.
    """

    # 1. Validation of the raw dict payload must succeed.
    question = Question.model_validate(payload)

    # 2. JSON serialisation must be stable under re-validation.
    as_json = question.model_dump(mode="json")
    question_again = Question.model_validate(as_json)
    as_json_again = question_again.model_dump(mode="json")

    # Field-level equality via the canonical JSON representation — this
    # avoids Decimal / Enum / None vs. missing-key ambiguities by
    # normalising everything through ``model_dump(mode="json")``.
    assert as_json == as_json_again


# ---------------------------------------------------------------------------
# Property 4b — rejection with populated ``loc`` and bounded messages.
# ---------------------------------------------------------------------------


# Per Requirement 3.9 / 13.9: the "实际取值摘要" embedded in any single
# validation error message must not exceed this bound. Pydantic v2 field
# validators produce short, structured messages that fit comfortably
# within this window; a regression — e.g. a custom ``model_validator``
# that dumps a full offending payload into the message — would be caught
# here.
_MAX_ERROR_MSG_CHARS = 200


@settings(max_examples=50, deadline=None)
@given(payload=invalid_question_payload_strategy())
def test_invalid_payload_raises_validation_error_with_loc(
    payload: dict[str, Any],
) -> None:
    """An invalid payload raises ``ValidationError`` with ``loc`` + bounded msg.

    Asserts three sub-properties per Requirement 3.9:

    1. ``Question.model_validate(payload)`` raises
       :class:`pydantic.ValidationError`.
    2. Every entry of ``err.errors()`` carries a ``loc`` key whose value
       is a *non-empty* tuple (the offending field path). This is the
       machine-readable "被拒字段名" from Requirement 3.9.
    3. Every entry's human-readable ``msg`` is ≤ 200 characters,
       matching the "实际取值摘要 ≤ 200 字符" clause.
    """

    with pytest.raises(ValidationError) as exc_info:
        Question.model_validate(payload)

    errors = exc_info.value.errors()

    # Pydantic always populates ``.errors()`` with at least one entry on
    # a failed ``model_validate``. If this ever regresses to an empty
    # list, the test must fail loudly rather than vacuously pass.
    assert len(errors) >= 1, "ValidationError must report at least one error"

    for err in errors:
        # --- (a) ``loc`` exists, is a tuple, and is non-empty ---------
        assert "loc" in err, f"validation error missing 'loc': {err!r}"
        loc = err["loc"]
        assert isinstance(loc, tuple), (
            f"validation error 'loc' must be a tuple, got {type(loc).__name__}"
        )
        assert len(loc) >= 1, (
            f"validation error 'loc' must be non-empty, got empty tuple: {err!r}"
        )

        # --- (b) ``msg`` is a bounded string --------------------------
        msg = err.get("msg", "")
        assert isinstance(msg, str), (
            f"validation error 'msg' must be a string, got {type(msg).__name__}"
        )
        assert len(msg) <= _MAX_ERROR_MSG_CHARS, (
            f"validation error 'msg' exceeds {_MAX_ERROR_MSG_CHARS} chars: "
            f"len={len(msg)}, loc={loc}"
        )
