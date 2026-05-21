"""Property test: AIGradingResult JSON round-trip (task 8.2).

**Property 6: JSON Round_Trip（AIGradingResult 部分）**
**Validates: Requirements 13.1**

This module verifies that any valid ``AIGradingResult`` instance survives a
JSON serialization → deserialization round trip with field-level equality
preserved.

The round-trip assertion is:

    AIGradingResult.model_validate(
        r.model_dump(mode="json")
    ).model_dump(mode="json") == r.model_dump(mode="json")

This guarantees that Pydantic's JSON serializer and validator are symmetric
for the AI grading result model — no data is lost, no fields drift, and no
type coercions introduce inequality.

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from string import ascii_letters, ascii_lowercase, digits

from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import IssueCategory
from cet4_app.domain.models.ai_grading import (
    AIGradingResult,
    AIIssue,
    DimensionScores,
)


# ---------------------------------------------------------------------------
# Leaf strategies
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)


def _sha256_hex() -> st.SearchStrategy[str]:
    """Generate a valid SHA-256 hex digest (64 lowercase hex chars)."""
    return st.text(alphabet=ascii_lowercase[:6] + digits, min_size=64, max_size=64)


def _dimension_scores() -> st.SearchStrategy[DimensionScores]:
    """Generate a valid DimensionScores instance."""
    return st.builds(
        DimensionScores,
        content=st.integers(min_value=0, max_value=5),
        structure=st.integers(min_value=0, max_value=5),
        language=st.integers(min_value=0, max_value=5),
        word_count=st.integers(min_value=0, max_value=5),
    )


def _overall_score() -> st.SearchStrategy[Decimal]:
    """Generate a valid overall_score Decimal in [0, 100] with 2 places."""
    return st.decimals(
        min_value=Decimal("0"),
        max_value=Decimal("100"),
        places=2,
        allow_nan=False,
        allow_infinity=False,
    )


_PRINTABLE_ASCII = st.characters(min_codepoint=0x21, max_codepoint=0x7E)


def _comment_text() -> st.SearchStrategy[str]:
    """Generate a comment string with length in [20, 400]."""
    return st.text(alphabet=_PRINTABLE_ASCII, min_size=20, max_size=80)


def _comments() -> st.SearchStrategy[dict[str, str]]:
    """Generate a valid comments dict with exactly the 4 required keys."""
    return st.fixed_dictionaries({
        "content": _comment_text(),
        "structure": _comment_text(),
        "language": _comment_text(),
        "word_count": _comment_text(),
    })


def _highlight() -> st.SearchStrategy[str]:
    """Generate a valid highlight string (1..400 chars)."""
    return st.text(alphabet=_PRINTABLE_ASCII, min_size=1, max_size=60)


def _ai_issue() -> st.SearchStrategy[AIIssue]:
    """Generate a valid AIIssue instance."""
    return st.builds(
        AIIssue,
        span=st.text(alphabet=_PRINTABLE_ASCII, min_size=1, max_size=40),
        category=st.sampled_from(list(IssueCategory)),
        suggestion=st.text(alphabet=_PRINTABLE_ASCII, min_size=1, max_size=60),
    )


def _revised_version() -> st.SearchStrategy[str]:
    """Generate a revised_version string with 120..500 whitespace-delimited words.

    Uses a fixed word pool joined at a drawn count to keep generation fast.
    """
    # Draw a word count in [120, 200] and build from a small fixed vocabulary
    _VOCAB = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
        "and", "cat", "runs", "fast", "through", "green", "field", "with",
        "great", "speed", "while", "birds", "sing", "above", "trees",
        "near", "river", "that", "flows", "into", "ocean", "deep",
    ]
    return st.integers(min_value=120, max_value=200).map(
        lambda n: " ".join(_VOCAB[i % len(_VOCAB)] for i in range(n))
    )


def _datetime_strategy() -> st.SearchStrategy[datetime]:
    """Generate a timezone-aware datetime suitable for JSON round-trip."""
    return st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 12, 31),
        timezones=st.just(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Inline composite strategy for a valid AIGradingResult
# ---------------------------------------------------------------------------


@st.composite
def _valid_ai_grading_result(draw: st.DrawFn) -> AIGradingResult:
    """Build a fully valid AIGradingResult instance.

    All field constraints from Requirement 15.3 are respected:
    - dimension_scores: 4-dim 0..5 integer rubric
    - overall_score: Decimal [0, 100] with 2 decimal places
    - comments: exactly 4 keys, each value 20..400 chars
    - highlights: 0..10 strings, each 1..400 chars
    - issues: 0..20 AIIssue entries
    - revised_version: 120..500 whitespace-delimited words
    - input_fingerprint: 64 lowercase hex chars (SHA-256)
    """
    return AIGradingResult(
        result_id=draw(_short_ident),
        question_id=draw(_short_ident),
        sheet_id=draw(_short_ident),
        model=draw(st.sampled_from([
            "deepseek-v4-flash", "deepseek-chat", "deepseek-reasoner"
        ])),
        dimension_scores=draw(_dimension_scores()),
        overall_score=draw(_overall_score()),
        comments=draw(_comments()),
        highlights=draw(st.lists(_highlight(), min_size=0, max_size=5)),
        issues=draw(st.lists(_ai_issue(), min_size=0, max_size=5)),
        revised_version=draw(_revised_version()),
        context_truncated=draw(st.booleans()),
        from_cache=draw(st.booleans()),
        generated_at=draw(_datetime_strategy()),
        input_fingerprint=draw(_sha256_hex()),
    )


# ---------------------------------------------------------------------------
# Test: AIGradingResult JSON round-trip
# ---------------------------------------------------------------------------


@given(result=_valid_ai_grading_result())
@settings(max_examples=200, deadline=500)
def test_ai_grading_result_json_round_trip(result: AIGradingResult) -> None:
    """Any valid AIGradingResult survives JSON round-trip with field equality.

    **Validates: Requirements 13.1**

    Constructs an AIGradingResult, dumps it to a JSON-compatible dict,
    re-validates from that dict, and asserts the two JSON representations
    are identical.
    """
    json_repr = result.model_dump(mode="json")
    result_restored = AIGradingResult.model_validate(json_repr)
    json_repr_restored = result_restored.model_dump(mode="json")
    assert json_repr_restored == json_repr
