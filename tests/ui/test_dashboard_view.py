"""Tests for DashboardView — progress visualization with metrics and charts.

Validates:
- Three key metric cards display correctly (Requirement 11.1)
- Exam date not set placeholder (Requirement 11.2)
- Time range switcher triggers refresh (Requirement 11.8)
- Empty data placeholder shown when no submissions (Requirement 11.6)
- Charts update with data (Requirements 11.3, 11.4, 11.5)
- Event-driven refresh (Requirement 11.7)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Optional

import pytest
from PySide6.QtWidgets import QMainWindow

from cet4_app.application.progress_service import (
    AccuracyDataPoint,
    DashboardSnapshot,
    ProgressService,
    TimeRange,
)
from cet4_app.domain.enums import QuestionType
from cet4_app.domain.progress.progress_calculator import (
    DashboardIndicators,
    MistakeDayAggregate,
    QuestionTypeAvgTime,
)
from cet4_app.ui.views.dashboard_view import DashboardView


# ---------------------------------------------------------------------------
# Fake data provider for testing
# ---------------------------------------------------------------------------


class FakeProgressDataProvider:
    """In-memory data provider for testing ProgressService."""

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
        self.submitted_count = submitted_count
        self.total_correct = total_correct
        self.total_graded = total_graded
        self.exam_date = exam_date
        self.accuracy_data = accuracy_data or []
        self.mistake_events = mistake_events or []
        self.time_records = time_records or {}

    def get_submitted_paper_count(self) -> int:
        return self.submitted_count

    def get_total_correct_and_graded(
        self, since: Optional[date] = None
    ) -> tuple[int, int]:
        return (self.total_correct, self.total_graded)

    def get_exam_date(self) -> Optional[date]:
        return self.exam_date

    def get_accuracy_by_section(
        self, since: Optional[date] = None
    ) -> list[AccuracyDataPoint]:
        return self.accuracy_data

    def get_mistake_events(
        self, since: Optional[date] = None
    ) -> list[tuple[date, str]]:
        return self.mistake_events

    def get_time_records(
        self, since: Optional[date] = None
    ) -> dict[QuestionType, list[int]]:
        return self.time_records


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def main_window(qtbot):
    """Create a main window for hosting the dashboard."""
    window = QMainWindow()
    window.resize(1024, 768)
    window.show()
    qtbot.addWidget(window)
    return window


@pytest.fixture
def empty_provider():
    """Provider with no data (no submissions)."""
    return FakeProgressDataProvider()


@pytest.fixture
def populated_provider():
    """Provider with sample data."""
    today = date.today()
    return FakeProgressDataProvider(
        submitted_count=6,
        total_correct=120,
        total_graded=180,
        exam_date=today + timedelta(days=10),
        accuracy_data=[
            AccuracyDataPoint(paper_index=1, section="listening", accuracy=65.0),
            AccuracyDataPoint(paper_index=2, section="listening", accuracy=72.0),
            AccuracyDataPoint(paper_index=1, section="reading", accuracy=58.0),
            AccuracyDataPoint(paper_index=2, section="reading", accuracy=70.0),
        ],
        mistake_events=[
            (today - timedelta(days=2), "new"),
            (today - timedelta(days=2), "new"),
            (today - timedelta(days=1), "new"),
            (today - timedelta(days=1), "pass"),
            (today, "pass"),
        ],
        time_records={
            QuestionType.listening_news: [30, 35, 28],
            QuestionType.reading_careful_choice: [90, 100, 85],
        },
    )


@pytest.fixture
def dashboard_empty(main_window, qtbot, empty_provider):
    """Dashboard with no data."""
    service = ProgressService(data_provider=empty_provider)
    view = DashboardView(progress_service=service, parent=main_window)
    qtbot.addWidget(view)
    return view


@pytest.fixture
def dashboard_populated(main_window, qtbot, populated_provider):
    """Dashboard with sample data."""
    service = ProgressService(data_provider=populated_provider)
    view = DashboardView(progress_service=service, parent=main_window)
    qtbot.addWidget(view)
    return view


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDashboardMetrics:
    """Tests for the three key metric cards (Requirement 11.1)."""

    def test_empty_state_shows_defaults(self, dashboard_empty: DashboardView):
        """With no data, metrics show 0% completion and dashes."""
        assert "0.0%" in dashboard_empty._completion_card._value_label.text()
        assert "--" in dashboard_empty._accuracy_card._value_label.text()

    def test_populated_completion_rate(self, dashboard_populated: DashboardView):
        """Completion rate shows correct percentage (6/12 = 50.0%)."""
        assert "50.0%" in dashboard_populated._completion_card._value_label.text()

    def test_populated_accuracy(self, dashboard_populated: DashboardView):
        """Overall accuracy shows correct value (120/180 = 66.7%)."""
        assert "66.7%" in dashboard_populated._accuracy_card._value_label.text()

    def test_populated_days_remaining(self, dashboard_populated: DashboardView):
        """Days remaining shows correct count."""
        assert "10" in dashboard_populated._days_card._value_label.text()
        assert "天" in dashboard_populated._days_card._value_label.text()


class TestExamDatePlaceholder:
    """Tests for exam date not set placeholder (Requirement 11.2)."""

    def test_no_exam_date_shows_placeholder(self, dashboard_empty: DashboardView):
        """When exam date is not set, placeholder is visible."""
        assert not dashboard_empty._exam_date_placeholder.isHidden()

    def test_exam_date_set_hides_placeholder(self, dashboard_populated: DashboardView):
        """When exam date is set, placeholder is hidden."""
        assert dashboard_populated._exam_date_placeholder.isHidden()

    def test_navigate_to_settings_signal(self, dashboard_empty: DashboardView, qtbot):
        """Clicking '立即设置' emits navigate_to_settings signal."""
        with qtbot.waitSignal(dashboard_empty.navigate_to_settings, timeout=1000):
            dashboard_empty._set_exam_date_btn.click()


class TestTimeRangeSwitcher:
    """Tests for time range switching (Requirement 11.8)."""

    def test_default_range_is_all(self, dashboard_populated: DashboardView):
        """Default time range is 'all'."""
        assert dashboard_populated._service.current_time_range == TimeRange.all
        assert dashboard_populated._range_buttons[TimeRange.all].isChecked()

    def test_switch_to_7_days(self, dashboard_populated: DashboardView):
        """Switching to 7 days updates the service range."""
        btn = dashboard_populated._range_buttons[TimeRange.last_7_days]
        btn.click()
        assert dashboard_populated._service.current_time_range == TimeRange.last_7_days

    def test_switch_to_14_days(self, dashboard_populated: DashboardView):
        """Switching to 14 days updates the service range."""
        btn = dashboard_populated._range_buttons[TimeRange.last_14_days]
        btn.click()
        assert dashboard_populated._service.current_time_range == TimeRange.last_14_days

    def test_switch_back_to_all(self, dashboard_populated: DashboardView):
        """Switching back to all works correctly."""
        # First switch to 7 days
        dashboard_populated._range_buttons[TimeRange.last_7_days].click()
        # Then back to all
        dashboard_populated._range_buttons[TimeRange.all].click()
        assert dashboard_populated._service.current_time_range == TimeRange.all


class TestEmptyDataPlaceholder:
    """Tests for empty data placeholder (Requirement 11.6)."""

    def test_charts_show_placeholder_when_empty(self, dashboard_empty: DashboardView):
        """Charts show placeholder text when no data exists."""
        # The chart widgets internally show placeholder when no data
        assert not dashboard_empty._accuracy_chart._has_data
        assert not dashboard_empty._mistake_chart._has_data
        assert not dashboard_empty._time_chart._has_data


class TestChartsWithData:
    """Tests for chart rendering with data (Requirements 11.3, 11.4, 11.5)."""

    def test_accuracy_chart_has_data(self, dashboard_populated: DashboardView):
        """Accuracy line chart shows data when available."""
        assert dashboard_populated._accuracy_chart._has_data

    def test_mistake_chart_has_data(self, dashboard_populated: DashboardView):
        """Mistake bar chart shows data when available."""
        assert dashboard_populated._mistake_chart._has_data

    def test_time_chart_has_data(self, dashboard_populated: DashboardView):
        """Time per type bar chart shows data when available."""
        assert dashboard_populated._time_chart._has_data


class TestEventDrivenRefresh:
    """Tests for event-driven refresh (Requirement 11.7)."""

    def test_on_answer_sheet_submitted_refreshes(
        self, main_window, qtbot
    ):
        """Submitting an answer sheet triggers dashboard refresh."""
        provider = FakeProgressDataProvider(submitted_count=0)
        service = ProgressService(data_provider=provider)
        view = DashboardView(progress_service=service, parent=main_window)
        qtbot.addWidget(view)

        # Initially 0%
        assert "0.0%" in view._completion_card._value_label.text()

        # Simulate submission
        provider.submitted_count = 3
        view.on_answer_sheet_submitted()

        # Should now show 25.0%
        assert "25.0%" in view._completion_card._value_label.text()

    def test_on_mistake_book_updated_refreshes(
        self, main_window, qtbot
    ):
        """Updating mistake book triggers dashboard refresh."""
        today = date.today()
        provider = FakeProgressDataProvider(
            submitted_count=1,
            total_correct=10,
            total_graded=20,
        )
        service = ProgressService(data_provider=provider)
        view = DashboardView(progress_service=service, parent=main_window)
        qtbot.addWidget(view)

        # Add mistake events
        provider.mistake_events = [(today, "new"), (today, "new")]
        view.on_mistake_book_updated()

        # Mistake chart should now have data
        assert view._mistake_chart._has_data
