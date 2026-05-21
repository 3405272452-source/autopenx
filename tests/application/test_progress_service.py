"""Unit tests for application/progress_service.py.

Validates:
- Requirements 11.1: Dashboard indicators (completion_rate, accuracy, days_remaining)
- Requirements 11.2: "Exam date not set" placeholder handling
- Requirements 11.6: Empty data placeholder
- Requirements 11.7: Refresh within 1 second after submission/mistake_book update
- Requirements 11.8: Time range switching with refresh within 500ms
"""

from __future__ import annotations

import time
from datetime import date, timedelta
from typing import Optional

import pytest

from cet4_app.domain.enums import QuestionType
from cet4_app.application.progress_service import (
    AccuracyDataPoint,
    DashboardSnapshot,
    ProgressDataProvider,
    ProgressService,
    TimeRange,
)


# ---------------------------------------------------------------------------
# Fake data provider for testing
# ---------------------------------------------------------------------------


class FakeProgressDataProvider:
    """In-memory implementation of ProgressDataProvider for testing."""

    def __init__(
        self,
        submitted_count: int = 0,
        total_correct: int = 0,
        total_graded: int = 0,
        exam_date: Optional[date] = None,
        accuracy_data: Optional[list[AccuracyDataPoint]] = None,
        mistake_events: Optional[list[tuple[date, str]]] = None,
        time_records: Optional[dict[QuestionType, list[int]]] = None,
    ) -> None:
        self._submitted_count = submitted_count
        self._total_correct = total_correct
        self._total_graded = total_graded
        self._exam_date = exam_date
        self._accuracy_data = accuracy_data or []
        self._mistake_events = mistake_events or []
        self._time_records = time_records or {}
        self.call_log: list[str] = []

    def get_submitted_paper_count(self) -> int:
        self.call_log.append("get_submitted_paper_count")
        return self._submitted_count

    def get_total_correct_and_graded(
        self, since: Optional[date] = None,
    ) -> tuple[int, int]:
        self.call_log.append(f"get_total_correct_and_graded(since={since})")
        return (self._total_correct, self._total_graded)

    def get_exam_date(self) -> Optional[date]:
        self.call_log.append("get_exam_date")
        return self._exam_date

    def get_accuracy_by_section(
        self, since: Optional[date] = None,
    ) -> list[AccuracyDataPoint]:
        self.call_log.append(f"get_accuracy_by_section(since={since})")
        return self._accuracy_data

    def get_mistake_events(
        self, since: Optional[date] = None,
    ) -> list[tuple[date, str]]:
        self.call_log.append(f"get_mistake_events(since={since})")
        return self._mistake_events

    def get_time_records(
        self, since: Optional[date] = None,
    ) -> dict[QuestionType, list[int]]:
        self.call_log.append(f"get_time_records(since={since})")
        return self._time_records


# ---------------------------------------------------------------------------
# Tests: Dashboard indicators (Requirement 11.1)
# ---------------------------------------------------------------------------


class TestDashboardIndicators:
    """Test dashboard key indicators computation."""

    def test_completion_rate_with_submissions(self) -> None:
        """Completion rate = submitted / 12 * 100, rounded to 1 decimal."""
        provider = FakeProgressDataProvider(submitted_count=5)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.indicators.completion_rate == 41.7  # 5/12*100

    def test_completion_rate_zero_submissions(self) -> None:
        """Zero submissions yields 0.0% completion rate."""
        provider = FakeProgressDataProvider(submitted_count=0)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.indicators.completion_rate == 0.0

    def test_completion_rate_all_submitted(self) -> None:
        """All 12 papers submitted yields 100.0%."""
        provider = FakeProgressDataProvider(submitted_count=12)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.indicators.completion_rate == 100.0

    def test_overall_accuracy_computed(self) -> None:
        """Overall accuracy = total_correct / total_graded * 100."""
        provider = FakeProgressDataProvider(
            submitted_count=3,
            total_correct=45,
            total_graded=60,
        )
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.indicators.overall_accuracy == 75.0

    def test_overall_accuracy_none_when_no_graded(self) -> None:
        """Overall accuracy is None when no questions have been graded."""
        provider = FakeProgressDataProvider(
            submitted_count=0,
            total_correct=0,
            total_graded=0,
        )
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.indicators.overall_accuracy is None

    def test_days_remaining_computed(self) -> None:
        """Days remaining computed from exam date."""
        exam = date.today() + timedelta(days=15)
        provider = FakeProgressDataProvider(exam_date=exam)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.indicators.days_remaining == 15


# ---------------------------------------------------------------------------
# Tests: Exam date not set (Requirement 11.2)
# ---------------------------------------------------------------------------


class TestExamDateNotSet:
    """Test handling when exam date is not configured."""

    def test_days_remaining_none_when_no_exam_date(self) -> None:
        """days_remaining is None when exam date is not set."""
        provider = FakeProgressDataProvider(exam_date=None)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.indicators.days_remaining is None


# ---------------------------------------------------------------------------
# Tests: Empty data placeholder (Requirement 11.6)
# ---------------------------------------------------------------------------


class TestEmptyDataPlaceholder:
    """Test placeholder behavior when no data exists."""

    def test_has_data_false_when_no_submissions(self) -> None:
        """has_data is False when no answer sheets submitted."""
        provider = FakeProgressDataProvider(submitted_count=0)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.has_data is False

    def test_has_data_true_when_submissions_exist(self) -> None:
        """has_data is True when at least one answer sheet submitted."""
        provider = FakeProgressDataProvider(submitted_count=1)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.has_data is True


# ---------------------------------------------------------------------------
# Tests: Time range switching (Requirement 11.8)
# ---------------------------------------------------------------------------


class TestTimeRangeSwitching:
    """Test time range switching and refresh latency."""

    def test_default_time_range_is_all(self) -> None:
        """Default time range is 'all'."""
        provider = FakeProgressDataProvider()
        service = ProgressService(data_provider=provider)

        assert service.current_time_range == TimeRange.all

    def test_switch_to_last_7_days(self) -> None:
        """Switching to last_7_days updates the current range."""
        provider = FakeProgressDataProvider(submitted_count=2)
        service = ProgressService(data_provider=provider)

        snapshot = service.switch_time_range(TimeRange.last_7_days)

        assert service.current_time_range == TimeRange.last_7_days
        assert snapshot.time_range == TimeRange.last_7_days

    def test_switch_to_last_14_days(self) -> None:
        """Switching to last_14_days updates the current range."""
        provider = FakeProgressDataProvider(submitted_count=2)
        service = ProgressService(data_provider=provider)

        snapshot = service.switch_time_range(TimeRange.last_14_days)

        assert service.current_time_range == TimeRange.last_14_days
        assert snapshot.time_range == TimeRange.last_14_days

    def test_switch_back_to_all(self) -> None:
        """Switching back to 'all' works correctly."""
        provider = FakeProgressDataProvider(submitted_count=2)
        service = ProgressService(data_provider=provider)

        service.switch_time_range(TimeRange.last_7_days)
        snapshot = service.switch_time_range(TimeRange.all)

        assert service.current_time_range == TimeRange.all
        assert snapshot.time_range == TimeRange.all

    def test_time_range_switch_passes_since_date_for_7_days(self) -> None:
        """last_7_days passes a since date 6 days ago."""
        provider = FakeProgressDataProvider(submitted_count=1)
        service = ProgressService(data_provider=provider)

        service.switch_time_range(TimeRange.last_7_days)

        # Check that the provider was called with a since date
        expected_since = date.today() - timedelta(days=6)
        assert any(
            f"since={expected_since}" in call
            for call in provider.call_log
        )

    def test_time_range_switch_passes_since_date_for_14_days(self) -> None:
        """last_14_days passes a since date 13 days ago."""
        provider = FakeProgressDataProvider(submitted_count=1)
        service = ProgressService(data_provider=provider)

        service.switch_time_range(TimeRange.last_14_days)

        expected_since = date.today() - timedelta(days=13)
        assert any(
            f"since={expected_since}" in call
            for call in provider.call_log
        )

    def test_time_range_all_passes_none_since(self) -> None:
        """'all' range passes since=None to the provider."""
        provider = FakeProgressDataProvider(submitted_count=1)
        service = ProgressService(data_provider=provider)

        service.switch_time_range(TimeRange.all)

        assert any("since=None" in call for call in provider.call_log)

    def test_switch_time_range_completes_within_500ms(self) -> None:
        """Time range switch must complete within 500ms (Req 11.8)."""
        provider = FakeProgressDataProvider(submitted_count=3)
        service = ProgressService(data_provider=provider)

        start = time.monotonic()
        service.switch_time_range(TimeRange.last_7_days)
        elapsed_ms = (time.monotonic() - start) * 1000

        assert elapsed_ms < 500


# ---------------------------------------------------------------------------
# Tests: Auto-refresh after events (Requirement 11.7)
# ---------------------------------------------------------------------------


class TestAutoRefresh:
    """Test auto-refresh within 1 second after events."""

    def test_on_answer_sheet_submitted_triggers_recompute(self) -> None:
        """Submission notification triggers recomputation."""
        provider = FakeProgressDataProvider(submitted_count=4)
        service = ProgressService(data_provider=provider)

        snapshot = service.on_answer_sheet_submitted()

        assert snapshot is not None
        assert snapshot.indicators.completion_rate == 33.3  # 4/12*100

    def test_on_mistake_book_updated_triggers_recompute(self) -> None:
        """Mistake book update notification triggers recomputation."""
        provider = FakeProgressDataProvider(
            submitted_count=2,
            mistake_events=[
                (date.today(), "new"),
                (date.today(), "new"),
                (date.today() - timedelta(days=1), "pass"),
            ],
        )
        service = ProgressService(data_provider=provider)

        snapshot = service.on_mistake_book_updated()

        assert snapshot is not None
        assert len(snapshot.mistake_bar_data) == 2  # 2 distinct days

    def test_on_answer_sheet_submitted_within_1_second(self) -> None:
        """Submission refresh must complete within 1 second (Req 11.7)."""
        provider = FakeProgressDataProvider(submitted_count=5)
        service = ProgressService(data_provider=provider)

        start = time.monotonic()
        service.on_answer_sheet_submitted()
        elapsed_ms = (time.monotonic() - start) * 1000

        assert elapsed_ms < 1000

    def test_on_mistake_book_updated_within_1_second(self) -> None:
        """Mistake book refresh must complete within 1 second (Req 11.7)."""
        provider = FakeProgressDataProvider(submitted_count=5)
        service = ProgressService(data_provider=provider)

        start = time.monotonic()
        service.on_mistake_book_updated()
        elapsed_ms = (time.monotonic() - start) * 1000

        assert elapsed_ms < 1000


# ---------------------------------------------------------------------------
# Tests: Chart data (Requirements 11.3, 11.4, 11.5)
# ---------------------------------------------------------------------------


class TestChartData:
    """Test chart data computation and passthrough."""

    def test_accuracy_line_data_passed_through(self) -> None:
        """Accuracy line chart data from provider is included in snapshot."""
        accuracy_data = [
            AccuracyDataPoint(paper_index=1, section="listening_news", accuracy=80.0),
            AccuracyDataPoint(paper_index=1, section="reading_careful_choice", accuracy=70.0),
            AccuracyDataPoint(paper_index=2, section="listening_news", accuracy=85.0),
        ]
        provider = FakeProgressDataProvider(
            submitted_count=2,
            accuracy_data=accuracy_data,
        )
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.accuracy_line_data == accuracy_data

    def test_mistake_bar_data_computed(self) -> None:
        """Mistake bar chart data is computed from events."""
        today = date.today()
        yesterday = today - timedelta(days=1)
        events = [
            (today, "new"),
            (today, "new"),
            (today, "pass"),
            (yesterday, "new"),
        ]
        provider = FakeProgressDataProvider(
            submitted_count=1,
            mistake_events=events,
        )
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert len(snapshot.mistake_bar_data) == 2
        # Sorted by date ascending
        assert snapshot.mistake_bar_data[0].day == yesterday
        assert snapshot.mistake_bar_data[0].new_mistakes == 1
        assert snapshot.mistake_bar_data[0].review_passes == 0
        assert snapshot.mistake_bar_data[1].day == today
        assert snapshot.mistake_bar_data[1].new_mistakes == 2
        assert snapshot.mistake_bar_data[1].review_passes == 1

    def test_time_per_type_data_computed(self) -> None:
        """Time per type bar chart data is computed from records."""
        time_records = {
            QuestionType.listening_news: [30, 40, 50],
            QuestionType.reading_careful_choice: [60, 80],
        }
        provider = FakeProgressDataProvider(
            submitted_count=1,
            time_records=time_records,
        )
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert len(snapshot.time_per_type_data) == 2
        # Check computed averages
        type_map = {r.question_type: r.avg_seconds for r in snapshot.time_per_type_data}
        assert type_map[QuestionType.listening_news] == 40  # (30+40+50)/3
        assert type_map[QuestionType.reading_careful_choice] == 70  # (60+80)/2

    def test_empty_chart_data_when_no_submissions(self) -> None:
        """Chart data is empty when no submissions exist."""
        provider = FakeProgressDataProvider(submitted_count=0)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert snapshot.accuracy_line_data == []
        assert snapshot.mistake_bar_data == []
        assert snapshot.time_per_type_data == []


# ---------------------------------------------------------------------------
# Tests: Last snapshot caching
# ---------------------------------------------------------------------------


class TestSnapshotCaching:
    """Test that the last computed snapshot is cached."""

    def test_last_snapshot_initially_none(self) -> None:
        """last_snapshot is None before first computation."""
        provider = FakeProgressDataProvider()
        service = ProgressService(data_provider=provider)

        assert service.last_snapshot is None

    def test_last_snapshot_updated_after_recompute(self) -> None:
        """last_snapshot is updated after recompute."""
        provider = FakeProgressDataProvider(submitted_count=3)
        service = ProgressService(data_provider=provider)

        snapshot = service.recompute()

        assert service.last_snapshot is snapshot

    def test_last_snapshot_updated_after_time_range_switch(self) -> None:
        """last_snapshot is updated after time range switch."""
        provider = FakeProgressDataProvider(submitted_count=3)
        service = ProgressService(data_provider=provider)

        snapshot = service.switch_time_range(TimeRange.last_7_days)

        assert service.last_snapshot is snapshot
