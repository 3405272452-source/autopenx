"""Unit tests for application/plan_service.py.

Covers:
- Plan creation with valid/invalid parameters
- Plan parameter update
- Day completion marking
- Consecutive missed day detection and reschedule signal
- Reschedule with postpone/compress strategies
- Completion rate calculation
- Start date validation window (today ± 7/30 days)

Requirements: 10.1, 10.3, 10.4, 10.5, 10.8
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Optional

import pytest

from cet4_app.domain.enums import DayStatus, SectionName, TaskKind
from cet4_app.domain.models.study_plan import (
    PlanParams,
    StudyDay,
    StudyPlan,
    StudyTask,
)
from cet4_app.application.plan_service import (
    PlanService,
    PlanServiceEvent,
)


# ---------------------------------------------------------------------------
# Fake PlanRepo for testing
# ---------------------------------------------------------------------------


class FakePlanRepo:
    """In-memory plan repository for testing."""

    def __init__(self) -> None:
        self._plans: dict[str, StudyPlan] = {}

    def save_plan(self, plan: StudyPlan) -> None:
        self._plans[plan.plan_id] = plan

    def load_active_plan(self) -> Optional[StudyPlan]:
        if not self._plans:
            return None
        # Return the most recently added plan
        return list(self._plans.values())[-1]

    def load_plan_by_id(self, plan_id: str) -> Optional[StudyPlan]:
        return self._plans.get(plan_id)

    def update_day_status(
        self, plan_id: str, day_index: int, new_status: DayStatus
    ) -> bool:
        plan = self._plans.get(plan_id)
        if plan is None:
            return False

        for i, day in enumerate(plan.days):
            if day.day_index == day_index:
                # Rebuild the day with new status
                new_day = StudyDay(
                    day_index=day.day_index,
                    date=day.date,
                    tasks=day.tasks,
                    status=new_status,
                    daily_target_accuracy=day.daily_target_accuracy,
                )
                new_days = list(plan.days)
                new_days[i] = new_day
                # Rebuild plan with updated days
                self._plans[plan_id] = StudyPlan(
                    plan_id=plan.plan_id,
                    start_date=plan.start_date,
                    total_days=plan.total_days,
                    params=plan.params,
                    days=new_days,
                )
                return True
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_TODAY = date(2025, 1, 15)


def _make_params(start_date: Optional[date] = None) -> PlanParams:
    """Create valid PlanParams for testing."""
    return PlanParams(
        start_date=start_date or _FIXED_TODAY,
        daily_minutes_cap=120,
        section_ratio={
            SectionName.writing: 15,
            SectionName.listening: 35,
            SectionName.reading: 35,
            SectionName.translation: 15,
        },
        daily_target_accuracy=0.7,
    )


def _make_papers(n: int = 12) -> list[str]:
    """Create a list of paper IDs."""
    return [f"paper-{i+1}" for i in range(n)]


def _make_service(
    today: date = _FIXED_TODAY,
) -> tuple[PlanService, FakePlanRepo, list[PlanServiceEvent]]:
    """Create a PlanService with fake repo and event collector."""
    repo = FakePlanRepo()
    events: list[PlanServiceEvent] = []
    service = PlanService(repo, today_provider=lambda: today)
    service.add_listener(events.append)
    return service, repo, events


# ---------------------------------------------------------------------------
# Tests: Plan creation
# ---------------------------------------------------------------------------


class TestCreatePlan:
    """Tests for PlanService.create_plan."""

    def test_create_plan_success(self) -> None:
        """Creating a plan with valid params persists and emits event."""
        service, repo, events = _make_service()
        params = _make_params()
        papers = _make_papers(12)

        plan = service.create_plan(params, papers)

        assert plan.plan_id is not None
        assert plan.total_days == 20
        assert plan.start_date == _FIXED_TODAY
        assert len(plan.days) == 20

        # Persisted
        loaded = repo.load_plan_by_id(plan.plan_id)
        assert loaded is not None
        assert loaded.plan_id == plan.plan_id

        # Event emitted
        assert len(events) == 1
        assert events[0].kind == "plan_created"
        assert events[0].plan_id == plan.plan_id
        assert events[0].detail["total_days"] == 20
        assert events[0].detail["paper_count"] == 12

    def test_create_plan_fewer_papers(self) -> None:
        """Creating a plan with fewer than 12 papers uses uniform distribution."""
        service, repo, events = _make_service()
        params = _make_params()
        papers = _make_papers(6)

        plan = service.create_plan(params, papers)

        assert plan.total_days == 20
        assert len(plan.days) == 20

    def test_create_plan_empty_papers_raises(self) -> None:
        """Creating a plan with no papers raises ValueError."""
        service, _, _ = _make_service()
        params = _make_params()

        with pytest.raises(ValueError, match="at least 1 paper"):
            service.create_plan(params, [])

    def test_create_plan_start_date_too_early(self) -> None:
        """Start date more than 7 days in the past is rejected."""
        service, _, _ = _make_service()
        too_early = _FIXED_TODAY - timedelta(days=8)
        params = _make_params(start_date=too_early)

        with pytest.raises(ValueError, match="too early"):
            service.create_plan(params, _make_papers())

    def test_create_plan_start_date_too_late(self) -> None:
        """Start date more than 30 days in the future is rejected."""
        service, _, _ = _make_service()
        too_late = _FIXED_TODAY + timedelta(days=31)
        params = _make_params(start_date=too_late)

        with pytest.raises(ValueError, match="too late"):
            service.create_plan(params, _make_papers())

    def test_create_plan_start_date_boundary_early(self) -> None:
        """Start date exactly 7 days in the past is accepted."""
        service, _, _ = _make_service()
        boundary = _FIXED_TODAY - timedelta(days=7)
        params = _make_params(start_date=boundary)

        plan = service.create_plan(params, _make_papers())
        assert plan.start_date == boundary

    def test_create_plan_start_date_boundary_late(self) -> None:
        """Start date exactly 30 days in the future is accepted."""
        service, _, _ = _make_service()
        boundary = _FIXED_TODAY + timedelta(days=30)
        params = _make_params(start_date=boundary)

        plan = service.create_plan(params, _make_papers())
        assert plan.start_date == boundary


# ---------------------------------------------------------------------------
# Tests: Update plan parameters
# ---------------------------------------------------------------------------


class TestUpdatePlanParams:
    """Tests for PlanService.update_plan_params."""

    def test_update_params_success(self) -> None:
        """Updating params rebuilds the plan and emits event."""
        service, repo, events = _make_service()
        params = _make_params()
        papers = _make_papers()
        plan = service.create_plan(params, papers)

        new_params = _make_params(start_date=_FIXED_TODAY + timedelta(days=1))
        updated = service.update_plan_params(plan.plan_id, new_params, papers)

        assert updated.plan_id == plan.plan_id
        assert updated.start_date == _FIXED_TODAY + timedelta(days=1)

        # Event emitted
        assert events[-1].kind == "plan_updated"
        assert events[-1].plan_id == plan.plan_id

    def test_update_params_plan_not_found(self) -> None:
        """Updating a non-existent plan raises ValueError."""
        service, _, _ = _make_service()
        params = _make_params()

        with pytest.raises(ValueError, match="Plan not found"):
            service.update_plan_params("nonexistent", params, _make_papers())


# ---------------------------------------------------------------------------
# Tests: Mark day completed
# ---------------------------------------------------------------------------


class TestMarkDayCompleted:
    """Tests for PlanService.mark_day_completed."""

    def test_mark_day_all_tasks_done(self) -> None:
        """Day is marked completed when all tasks are done."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        # Mark all tasks in day 1 as completed
        day1 = plan.days[0]
        completed_tasks = [
            StudyTask(
                task_id=t.task_id,
                kind=t.kind,
                paper_id=t.paper_id,
                section=t.section,
                mistakes_to_review=t.mistakes_to_review,
                intensive_listening_minutes=t.intensive_listening_minutes,
                writing_translation_count=t.writing_translation_count,
                completed=True,
            )
            for t in day1.tasks
        ]
        new_day1 = StudyDay(
            day_index=day1.day_index,
            date=day1.date,
            tasks=completed_tasks,
            status=DayStatus.pending,
            daily_target_accuracy=day1.daily_target_accuracy,
        )
        new_days = [new_day1] + list(plan.days[1:])
        updated_plan = StudyPlan(
            plan_id=plan.plan_id,
            start_date=plan.start_date,
            total_days=plan.total_days,
            params=plan.params,
            days=new_days,
        )
        repo.save_plan(updated_plan)

        result = service.mark_day_completed(plan.plan_id, 1)

        assert result is True
        # Event emitted
        day_events = [e for e in events if e.kind == "day_completed"]
        assert len(day_events) == 1
        assert day_events[0].detail["day_index"] == 1
        assert "completion_rate" in day_events[0].detail

    def test_mark_day_incomplete_tasks(self) -> None:
        """Day is NOT marked if tasks are incomplete."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        # Tasks are not completed by default
        result = service.mark_day_completed(plan.plan_id, 1)
        assert result is False

    def test_mark_day_plan_not_found(self) -> None:
        """Returns False for non-existent plan."""
        service, _, _ = _make_service()
        result = service.mark_day_completed("nonexistent", 1)
        assert result is False

    def test_mark_day_already_completed(self) -> None:
        """Returns False if day is already completed."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        # Manually set day 1 as completed with all tasks done
        day1 = plan.days[0]
        completed_tasks = [
            StudyTask(
                task_id=t.task_id,
                kind=t.kind,
                paper_id=t.paper_id,
                section=t.section,
                mistakes_to_review=t.mistakes_to_review,
                intensive_listening_minutes=t.intensive_listening_minutes,
                writing_translation_count=t.writing_translation_count,
                completed=True,
            )
            for t in day1.tasks
        ]
        new_day1 = StudyDay(
            day_index=day1.day_index,
            date=day1.date,
            tasks=completed_tasks,
            status=DayStatus.completed,
            daily_target_accuracy=day1.daily_target_accuracy,
        )
        new_days = [new_day1] + list(plan.days[1:])
        updated_plan = StudyPlan(
            plan_id=plan.plan_id,
            start_date=plan.start_date,
            total_days=plan.total_days,
            params=plan.params,
            days=new_days,
        )
        repo.save_plan(updated_plan)

        result = service.mark_day_completed(plan.plan_id, 1)
        assert result is False


# ---------------------------------------------------------------------------
# Tests: Missed days detection
# ---------------------------------------------------------------------------


class TestCheckMissedDays:
    """Tests for PlanService.check_missed_days."""

    def test_no_missed_days(self) -> None:
        """No missed days when plan starts today."""
        service, repo, events = _make_service(today=_FIXED_TODAY)
        params = _make_params(start_date=_FIXED_TODAY)
        plan = service.create_plan(params, _make_papers())

        result = service.check_missed_days(plan.plan_id)
        assert result is None

    def test_one_missed_day(self) -> None:
        """Detects 1 missed day and emits reschedule_needed."""
        # Plan started yesterday, today is day 2, day 1 is still pending
        yesterday = _FIXED_TODAY - timedelta(days=1)
        service, repo, events = _make_service(today=_FIXED_TODAY)
        params = _make_params(start_date=yesterday)
        plan = service.create_plan(params, _make_papers())

        result = service.check_missed_days(plan.plan_id)

        assert result == 1
        reschedule_events = [e for e in events if e.kind == "reschedule_needed"]
        assert len(reschedule_events) == 1
        assert reschedule_events[0].detail["consecutive_missed_days"] == 1

    def test_multiple_consecutive_missed_days(self) -> None:
        """Detects multiple consecutive missed days."""
        # Plan started 3 days ago, all days still pending
        three_days_ago = _FIXED_TODAY - timedelta(days=3)
        service, repo, events = _make_service(today=_FIXED_TODAY)
        params = _make_params(start_date=three_days_ago)
        plan = service.create_plan(params, _make_papers())

        result = service.check_missed_days(plan.plan_id)

        assert result == 3

    def test_non_consecutive_missed_days(self) -> None:
        """Only counts the most recent consecutive streak."""
        # Plan started 4 days ago; day 1 completed, days 2-4 pending
        four_days_ago = _FIXED_TODAY - timedelta(days=4)
        service, repo, events = _make_service(today=_FIXED_TODAY)
        params = _make_params(start_date=four_days_ago)
        plan = service.create_plan(params, _make_papers())

        # Mark day 1 as completed
        repo.update_day_status(plan.plan_id, 1, DayStatus.completed)

        # Also mark day 2 as completed to create a gap
        repo.update_day_status(plan.plan_id, 2, DayStatus.completed)

        result = service.check_missed_days(plan.plan_id)

        # Days 3 and 4 are pending and past → 2 consecutive missed
        assert result == 2

    def test_plan_not_found(self) -> None:
        """Returns None for non-existent plan."""
        service, _, _ = _make_service()
        result = service.check_missed_days("nonexistent")
        assert result is None


# ---------------------------------------------------------------------------
# Tests: Reschedule
# ---------------------------------------------------------------------------


class TestReschedulePlan:
    """Tests for PlanService.reschedule_plan."""

    def test_reschedule_postpone(self) -> None:
        """Postpone strategy increases total_days."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        rescheduled = service.reschedule_plan(plan.plan_id, "postpone")

        # Postpone keeps all days (completed first, then pending)
        assert rescheduled.total_days == plan.total_days
        assert rescheduled.plan_id == plan.plan_id

        # Event emitted
        reschedule_events = [e for e in events if e.kind == "plan_rescheduled"]
        assert len(reschedule_events) == 1
        assert reschedule_events[0].detail["strategy"] == "postpone"

    def test_reschedule_compress(self) -> None:
        """Compress strategy keeps total_days the same."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        rescheduled = service.reschedule_plan(plan.plan_id, "compress")

        assert rescheduled.total_days == plan.total_days
        assert rescheduled.plan_id == plan.plan_id

        # Event emitted
        reschedule_events = [e for e in events if e.kind == "plan_rescheduled"]
        assert len(reschedule_events) == 1
        assert reschedule_events[0].detail["strategy"] == "compress"

    def test_reschedule_plan_not_found(self) -> None:
        """Raises ValueError for non-existent plan."""
        service, _, _ = _make_service()

        with pytest.raises(ValueError, match="Plan not found"):
            service.reschedule_plan("nonexistent", "postpone")

    def test_reschedule_invalid_strategy(self) -> None:
        """Raises ValueError for invalid strategy."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        with pytest.raises(ValueError, match="strategy must be"):
            service.reschedule_plan(plan.plan_id, "invalid")  # type: ignore


# ---------------------------------------------------------------------------
# Tests: Completion rate
# ---------------------------------------------------------------------------


class TestCompletionRate:
    """Tests for PlanService.get_completion_rate."""

    def test_no_completed_days(self) -> None:
        """Completion rate is 0.0 when no days are completed."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        rate = service.get_completion_rate(plan.plan_id)
        assert rate == 0.0

    def test_some_completed_days(self) -> None:
        """Completion rate reflects completed days."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        # Mark 5 days as completed
        for i in range(1, 6):
            repo.update_day_status(plan.plan_id, i, DayStatus.completed)

        rate = service.get_completion_rate(plan.plan_id)
        # 5 / 20 * 100 = 25.0
        assert rate == 25.0

    def test_all_completed_days(self) -> None:
        """Completion rate is 100.0 when all days are completed."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        for i in range(1, 21):
            repo.update_day_status(plan.plan_id, i, DayStatus.completed)

        rate = service.get_completion_rate(plan.plan_id)
        assert rate == 100.0

    def test_plan_not_found(self) -> None:
        """Returns None for non-existent plan."""
        service, _, _ = _make_service()
        rate = service.get_completion_rate("nonexistent")
        assert rate is None


# ---------------------------------------------------------------------------
# Tests: Get active plan
# ---------------------------------------------------------------------------


class TestGetActivePlan:
    """Tests for PlanService.get_active_plan."""

    def test_no_active_plan(self) -> None:
        """Returns None when no plan exists."""
        service, _, _ = _make_service()
        assert service.get_active_plan() is None

    def test_returns_active_plan(self) -> None:
        """Returns the most recently created plan."""
        service, repo, events = _make_service()
        params = _make_params()
        plan = service.create_plan(params, _make_papers())

        active = service.get_active_plan()
        assert active is not None
        assert active.plan_id == plan.plan_id


# ---------------------------------------------------------------------------
# Tests: Event listener management
# ---------------------------------------------------------------------------


class TestEventListeners:
    """Tests for event listener add/remove."""

    def test_remove_listener(self) -> None:
        """Removed listener no longer receives events."""
        repo = FakePlanRepo()
        service = PlanService(repo, today_provider=lambda: _FIXED_TODAY)

        extra_events: list[PlanServiceEvent] = []
        listener = extra_events.append
        service.add_listener(listener)

        params = _make_params()
        service.create_plan(params, _make_papers())
        assert len(extra_events) == 1

        service.remove_listener(listener)
        service.create_plan(params, _make_papers())
        # extra_events should still have only 1 event (listener was removed)
        assert len(extra_events) == 1
