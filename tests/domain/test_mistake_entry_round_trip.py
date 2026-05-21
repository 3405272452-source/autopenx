"""Property test: MistakeEntry JSON round-trip (task 6.2).

**Property 6: JSON Round_Trip（MistakeEntry 部分）**
**Validates: Requirements 13.1, 13.5**

This module verifies that any valid ``MistakeEntry`` survives a JSON
serialization → deserialization round trip with field-level equality
preserved.

The round-trip assertion is:

    MistakeEntry.model_validate(
        entry.model_dump(mode="json")
    ).model_dump(mode="json") == entry.model_dump(mode="json")

This guarantees that Pydantic's JSON serializer and validator are
symmetric for MistakeEntry — no data is lost, no fields drift, and no
type coercions introduce inequality (Requirement 13.5).

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from string import ascii_letters, digits

from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.models.mistake_entry import MistakeEntry


# ---------------------------------------------------------------------------
# Inline composite strategy for valid MistakeEntry
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)
_question_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=64)
_tag_text = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=32)
_notes_text = st.text(min_size=0, max_size=200)

# Timestamps: use aware datetimes within a reasonable range to avoid
# serialization edge cases with extreme dates.
_aware_datetime = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31),
    timezones=st.just(timezone.utc),
)


@st.composite
def _valid_mistake_entry_strategy(draw: st.DrawFn) -> MistakeEntry:
    """Build a valid MistakeEntry respecting all model invariants.

    Invariants enforced:
    - last_wrong_at >= first_wrong_at (temporal ordering)
    - mastered=True => correct_streak >= 2
    - error_count >= 1 (PositiveInt)
    - redo_count >= 0, correct_streak >= 0
    - notes max 1000 chars, tags max 20 items each 1-32 chars
    """
    # Generate two timestamps and ensure ordering
    dt1 = draw(_aware_datetime)
    dt2 = draw(_aware_datetime)
    first_wrong_at = min(dt1, dt2)
    last_wrong_at = max(dt1, dt2)

    # Generate mastered and correct_streak with invariant
    mastered = draw(st.booleans())
    if mastered:
        correct_streak = draw(st.integers(min_value=2, max_value=50))
    else:
        correct_streak = draw(st.integers(min_value=0, max_value=50))

    entry = MistakeEntry(
        entry_id=draw(_short_ident),
        question_id=draw(_question_ident),
        paper_id=draw(_short_ident),
        first_wrong_at=first_wrong_at,
        last_wrong_at=last_wrong_at,
        error_count=draw(st.integers(min_value=1, max_value=100)),
        redo_count=draw(st.integers(min_value=0, max_value=200)),
        correct_streak=correct_streak,
        mastered=mastered,
        notes=draw(_notes_text),
        tags=draw(st.lists(_tag_text, min_size=0, max_size=5)),
    )
    return entry


# ---------------------------------------------------------------------------
# Test: MistakeEntry JSON round-trip
# ---------------------------------------------------------------------------


@given(entry=_valid_mistake_entry_strategy())
@settings(max_examples=200, deadline=500)
def test_mistake_entry_json_round_trip(entry: MistakeEntry) -> None:
    """Any valid MistakeEntry survives JSON round-trip with field equality.

    **Validates: Requirements 13.1, 13.5**

    Dumps the MistakeEntry to a JSON-compatible dict via model_dump(mode="json"),
    re-validates from that dict, and asserts the two JSON representations are
    identical.
    """
    json_repr = entry.model_dump(mode="json")
    entry_restored = MistakeEntry.model_validate(json_repr)
    json_repr_restored = entry_restored.model_dump(mode="json")
    assert json_repr_restored == json_repr
