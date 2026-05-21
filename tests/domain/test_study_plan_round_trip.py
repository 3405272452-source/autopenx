"""Property test: StudyPlan JSON round-trip (task 7.2).

**Property 6: JSON Round_Trip（StudyPlan 部分）**
**Validates: Requirements 13.1, 13.6**

This module verifies that any valid ``StudyPlan`` instance survives a JSON
serialization → deserialization round trip with field-level equality preserved.

The round-trip assertion is:

    StudyPlan.model_validate(plan.model_dump(mode="json")).model_dump(mode="json")
        == plan.model_dump(mode="json")

This guarantees that Pydantic's JSON serializer and validator are symmetric —
no data is lost, no fields drift, and no type coercions introduce inequality
(Requirement 13.6).

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

from datetime import date, timedelta
from string import ascii_letters, digits

from hypothesis import given, settings
from hypothesis import strategies as st

from cet4_app.domain.enums import DayStatus, SectionName, TaskKind
from cet4_app.domain.models.study_plan import (
    PlanParams,
    StudyDay,
    StudyPlan,
    StudyTask,
)

# ---------------------------------------------------------------------------
# Shared strategy building blocks
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)

# daily_minutes_cap must be a multiple of 15 in [30, 480]
_valid_minutes_cap = st.sampled_from(list(range(30, 481, 15)))

# section_ratio: 4 values in [0, 100] that sum to 100
@st.composite
def _valid_section_ratio(draw: st.DrawFn) -> dict[SectionName, int]:
    """Generate a valid section_ratio dict: 4 values in [0, 100] summing to 100."""
    # Draw 3 cut points in [0, 100], sort them, derive 4 segments
    cuts = sorted(draw(st.lists(st.integers(min_value=0, max_value=100), min_size=3, max_size=3)))
    values = [
        cuts[0],
        cuts[1] - cuts[0],
        cuts[2] - cuts[1],
        100 - cuts[2],
    ]
    sections = list(SectionName)
    return dict(zip(sections, values))


_daily_target_accuracy = st.one_of(
    st.none(),
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
)

_task_kind = st.sampled_from(list(TaskKind))
_day_status = st.sampled_from(list(DayStatus))
_optional_section = st.one_of(st.none(), st.sampled_from(list(SectionName)))


# ---------------------------------------------------------------------------
# Inline composite strategy for a valid StudyPlan
# ---------------------------------------------------------------------------


@st.composite
def _valid_study_plan(draw: st.DrawFn) -> StudyPlan:
    """Build a valid StudyPlan with consistent calendar invariants.

    Generates a plan with 1–30 days, each day containing 0–3 tasks,
    ensuring all model validators pass (day_index, date sequence, params).
    """
    plan_id = draw(_short_ident)
    total_days = draw(st.integers(min_value=1, max_value=30))
    start_date = draw(
        st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 12, 31))
    )

    # Build PlanParams
    section_ratio = draw(_valid_section_ratio())
    daily_minutes_cap = draw(_valid_minutes_cap)
    target_accuracy = draw(_daily_target_accuracy)

    params = PlanParams(
        start_date=start_date,
        daily_minutes_cap=daily_minutes_cap,
        section_ratio=section_ratio,
        daily_target_accuracy=target_accuracy,
    )

    # Build days with correct day_index and date sequence
    days: list[StudyDay] = []
    for i in range(total_days):
        num_tasks = draw(st.integers(min_value=0, max_value=3))
        tasks: list[StudyTask] = []
        for t in range(num_tasks):
            task = StudyTask(
                task_id=draw(_short_ident),
                kind=draw(_task_kind),
                paper_id=draw(st.one_of(st.none(), _short_ident)),
                section=draw(_optional_section),
                mistakes_to_review=draw(st.integers(min_value=0, max_value=200)),
                intensive_listening_minutes=draw(st.integers(min_value=0, max_value=180)),
                writing_translation_count=draw(st.integers(min_value=0, max_value=10)),
                completed=draw(st.booleans()),
            )
            tasks.append(task)

        day = StudyDay(
            day_index=i + 1,
            date=start_date + timedelta(days=i),
            tasks=tasks,
            status=draw(_day_status),
            daily_target_accuracy=draw(_daily_target_accuracy),
        )
        days.append(day)

    plan = StudyPlan(
        plan_id=plan_id,
        start_date=start_date,
        total_days=total_days,
        params=params,
        days=days,
    )
    return plan


# ---------------------------------------------------------------------------
# Test: StudyPlan JSON round-trip
# ---------------------------------------------------------------------------


@given(plan=_valid_study_plan())
@settings(max_examples=200, deadline=500)
def test_study_plan_json_round_trip(plan: StudyPlan) -> None:
    """Any valid StudyPlan survives JSON round-trip with field equality.

    **Validates: Requirements 13.1, 13.6**

    Dumps the StudyPlan to a JSON-compatible dict, re-validates from that dict,
    and asserts the two JSON representations are identical.
    """
    json_repr = plan.model_dump(mode="json")
    plan_restored = StudyPlan.model_validate(json_repr)
    json_repr_restored = plan_restored.model_dump(mode="json")
    assert json_repr_restored == json_repr
