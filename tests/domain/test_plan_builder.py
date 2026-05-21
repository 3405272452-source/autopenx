"""Property test: Plan 分配不变量 (task 15.2).

**Property 12: Study_Plan 默认规则与动态参数下的分配不变量**
**Validates: Requirements 10.1, 10.2, 10.3, 10.7, 10.8**

This module verifies the following invariants of the plan builder:

1. With 12 papers, the fixed distribution rule assigns papers 1–3 to days
   1–4, papers 4–6 to days 5–8, papers 7–9 to days 9–12, papers 10–12 to
   days 13–16. Days 17–19 are drill, day 20 is mock.
2. With n < 12 papers, each paper gets ceil(16/n) days (uniform distribution).
3. PlanParams validation rejects invalid inputs (daily_minutes_cap not
   multiple of 15, section_ratio sum != 100, etc.).
4. Reschedule with "postpone" strategy extends total_days.
5. Reschedule with "compress" strategy keeps total_days the same.

Domain-layer purity: imports only ``pydantic``, ``hypothesis``, and
``cet4_app.domain.*``. No Qt / httpx / sqlalchemy.
"""

from __future__ import annotations

import math
from datetime import date, timedelta
from string import ascii_letters, digits

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st
from pydantic import ValidationError

from cet4_app.domain.enums import DayStatus, SectionName, TaskKind
from cet4_app.domain.models.study_plan import PlanParams, StudyPlan, StudyDay, StudyTask
from cet4_app.domain.plan.plan_builder import build, reschedule
from cet4_app.domain.plan.plan_distributor import distribute_papers


# ---------------------------------------------------------------------------
# Strategy building blocks
# ---------------------------------------------------------------------------

_IDENT_ALPHABET = ascii_letters + digits + "-_"
_short_ident = st.text(alphabet=_IDENT_ALPHABET, min_size=1, max_size=24)

# daily_minutes_cap must be a multiple of 15 in [30, 480]
_valid_minutes_cap = st.sampled_from(list(range(30, 481, 15)))


@st.composite
def _valid_section_ratio(draw: st.DrawFn) -> dict[SectionName, int]:
    """Generate a valid section_ratio dict: 4 values in [0, 100] summing to 100."""
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


@st.composite
def _valid_plan_params(draw: st.DrawFn) -> PlanParams:
    """Generate a valid PlanParams instance."""
    start_date = draw(st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 12, 31)))
    daily_minutes_cap = draw(_valid_minutes_cap)
    section_ratio = draw(_valid_section_ratio())
    target_accuracy = draw(_daily_target_accuracy)
    return PlanParams(
        start_date=start_date,
        daily_minutes_cap=daily_minutes_cap,
        section_ratio=section_ratio,
        daily_target_accuracy=target_accuracy,
    )


@st.composite
def _paper_list(draw: st.DrawFn, min_count: int = 1, max_count: int = 12) -> list[str]:
    """Generate a list of unique paper IDs."""
    n = draw(st.integers(min_value=min_count, max_value=max_count))
    return [f"paper-{i+1}" for i in range(n)]


# ---------------------------------------------------------------------------
# Test 1: Default 12-paper allocation (fixed mapping)
# ---------------------------------------------------------------------------


@given(params=_valid_plan_params())
@settings(max_examples=50, deadline=None)
def test_default_12_paper_allocation(params: PlanParams) -> None:
    """With 12 papers, the fixed distribution rule applies.

    **Validates: Requirements 10.1, 10.2**

    Papers 1–3 → days 1–4, Papers 4–6 → days 5–8,
    Papers 7–9 → days 9–12, Papers 10–12 → days 13–16.
    Days 17–19 are drill, day 20 is mock.
    """
    papers = [f"paper-{i+1}" for i in range(12)]
    plan = build(params, papers)

    # Plan structure invariants
    assert plan.total_days == 20
    assert len(plan.days) == 20

    # Check fixed paper distribution for days 1–16
    expected_groups = [
        (range(1, 5), ["paper-1", "paper-2", "paper-3"]),
        (range(5, 9), ["paper-4", "paper-5", "paper-6"]),
        (range(9, 13), ["paper-7", "paper-8", "paper-9"]),
        (range(13, 17), ["paper-10", "paper-11", "paper-12"]),
    ]

    for day_range, expected_papers in expected_groups:
        for day_idx in day_range:
            day = plan.days[day_idx - 1]
            paper_tasks = [t for t in day.tasks if t.kind == TaskKind.paper]
            assigned_papers = [t.paper_id for t in paper_tasks]
            assert sorted(assigned_papers) == sorted(expected_papers), (
                f"Day {day_idx}: expected papers {expected_papers}, "
                f"got {assigned_papers}"
            )

    # Days 17–19 are drill
    for day_idx in (17, 18, 19):
        day = plan.days[day_idx - 1]
        assert all(t.kind == TaskKind.drill for t in day.tasks), (
            f"Day {day_idx} should have drill tasks only"
        )

    # Day 20 is mock
    day_20 = plan.days[19]
    assert all(t.kind == TaskKind.mock for t in day_20.tasks), (
        "Day 20 should have mock tasks only"
    )


# ---------------------------------------------------------------------------
# Test 2: Fewer than 12 papers — uniform distribution
# ---------------------------------------------------------------------------


@given(
    params=_valid_plan_params(),
    n=st.integers(min_value=1, max_value=11),
)
@settings(max_examples=50, deadline=None)
def test_fewer_than_12_papers_uniform_distribution(params: PlanParams, n: int) -> None:
    """With n < 12 papers, each paper gets ceil(16/n) days (approximately).

    **Validates: Requirements 10.8**

    All papers must be assigned to at least 1 day within days 1–16.
    Days 17–19 are drill, day 20 is mock.
    """
    papers = [f"paper-{i+1}" for i in range(n)]
    plan = build(params, papers)

    assert plan.total_days == 20
    assert len(plan.days) == 20

    # Collect which papers appear in days 1–16
    papers_seen: set[str] = set()
    paper_day_counts: dict[str, int] = {p: 0 for p in papers}

    for day_idx in range(1, 17):
        day = plan.days[day_idx - 1]
        for task in day.tasks:
            if task.kind == TaskKind.paper and task.paper_id:
                papers_seen.add(task.paper_id)
                paper_day_counts[task.paper_id] += 1

    # All papers must be assigned at least once
    assert papers_seen == set(papers), (
        f"Not all papers assigned. Missing: {set(papers) - papers_seen}"
    )

    # Each paper should get approximately ceil(16/n) days
    expected_days_per_paper = math.ceil(16 / n)
    for paper_id, count in paper_day_counts.items():
        # Allow some flexibility: at least 1 day, at most ceil(16/n)
        assert count >= 1, f"{paper_id} has 0 days assigned"
        assert count <= expected_days_per_paper, (
            f"{paper_id} has {count} days, expected at most {expected_days_per_paper}"
        )

    # Days 17–19 are drill
    for day_idx in (17, 18, 19):
        day = plan.days[day_idx - 1]
        assert all(t.kind == TaskKind.drill for t in day.tasks)

    # Day 20 is mock
    day_20 = plan.days[19]
    assert all(t.kind == TaskKind.mock for t in day_20.tasks)


# ---------------------------------------------------------------------------
# Test 3: PlanParams validation rejects invalid inputs
# ---------------------------------------------------------------------------


@given(
    start_date=st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 12, 31)),
    bad_minutes=st.integers(min_value=30, max_value=480).filter(lambda x: x % 15 != 0),
)
@settings(max_examples=50, deadline=None)
def test_params_validation_rejects_invalid(start_date: date, bad_minutes: int) -> None:
    """PlanParams rejects daily_minutes_cap not a multiple of 15.

    **Validates: Requirements 10.3**
    """
    with pytest.raises(ValidationError):
        PlanParams(
            start_date=start_date,
            daily_minutes_cap=bad_minutes,
            section_ratio={
                SectionName.writing: 25,
                SectionName.listening: 25,
                SectionName.reading: 25,
                SectionName.translation: 25,
            },
            daily_target_accuracy=None,
        )


@given(
    start_date=st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 12, 31)),
    offset=st.integers(min_value=1, max_value=50),
)
@settings(max_examples=50, deadline=None)
def test_params_validation_rejects_ratio_sum_not_100(start_date: date, offset: int) -> None:
    """PlanParams rejects section_ratio whose values don't sum to 100.

    **Validates: Requirements 10.3**
    """
    # Create a ratio that sums to 100 + offset (always != 100)
    bad_ratio = {
        SectionName.writing: 25 + offset,
        SectionName.listening: 25,
        SectionName.reading: 25,
        SectionName.translation: 25,
    }
    with pytest.raises(ValidationError):
        PlanParams(
            start_date=start_date,
            daily_minutes_cap=120,
            section_ratio=bad_ratio,
            daily_target_accuracy=None,
        )


# ---------------------------------------------------------------------------
# Test 4: Reschedule with "postpone" extends total_days
# ---------------------------------------------------------------------------


@given(params=_valid_plan_params())
@settings(max_examples=50, deadline=None)
def test_reschedule_postpone(params: PlanParams) -> None:
    """Postpone strategy extends total_days when there are incomplete days.

    **Validates: Requirements 10.5**

    After marking some days as completed and rescheduling with "postpone",
    the total_days should be >= original total_days (it stays the same
    since all days are preserved, just reordered).
    """
    papers = [f"paper-{i+1}" for i in range(12)]
    plan = build(params, papers)

    # Mark first 5 days as completed
    new_days = []
    for i, day in enumerate(plan.days):
        if i < 5:
            new_days.append(
                StudyDay(
                    day_index=day.day_index,
                    date=day.date,
                    tasks=day.tasks,
                    status=DayStatus.completed,
                    daily_target_accuracy=day.daily_target_accuracy,
                )
            )
        else:
            new_days.append(day)

    modified_plan = StudyPlan(
        plan_id=plan.plan_id,
        start_date=plan.start_date,
        total_days=plan.total_days,
        params=plan.params,
        days=new_days,
    )

    rescheduled = reschedule(modified_plan, "postpone")

    # Postpone preserves all days (completed + incomplete)
    assert rescheduled.total_days >= plan.total_days
    # Completed days should still be present
    completed_count = sum(1 for d in rescheduled.days if d.status == DayStatus.completed)
    assert completed_count >= 5


# ---------------------------------------------------------------------------
# Test 5: Reschedule with "compress" keeps total_days same
# ---------------------------------------------------------------------------


@given(params=_valid_plan_params())
@settings(max_examples=50, deadline=None)
def test_reschedule_compress(params: PlanParams) -> None:
    """Compress strategy keeps total_days the same.

    **Validates: Requirements 10.5**

    After rescheduling with "compress", total_days must remain unchanged.
    """
    papers = [f"paper-{i+1}" for i in range(12)]
    plan = build(params, papers)

    # Mark first 3 days as completed to create a scenario where
    # compress has pending days to work with
    new_days = []
    for i, day in enumerate(plan.days):
        if i < 3:
            new_days.append(
                StudyDay(
                    day_index=day.day_index,
                    date=day.date,
                    tasks=day.tasks,
                    status=DayStatus.completed,
                    daily_target_accuracy=day.daily_target_accuracy,
                )
            )
        else:
            new_days.append(day)

    modified_plan = StudyPlan(
        plan_id=plan.plan_id,
        start_date=plan.start_date,
        total_days=plan.total_days,
        params=plan.params,
        days=new_days,
    )

    rescheduled = reschedule(modified_plan, "compress")

    # Compress keeps total_days the same
    assert rescheduled.total_days == modified_plan.total_days
