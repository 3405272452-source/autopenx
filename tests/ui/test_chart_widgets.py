"""Tests for chart widgets — LineChartWidget and BarChartWidget."""

from __future__ import annotations

import csv
import io
import tempfile
from pathlib import Path

import pytest
from PySide6.QtWidgets import QMainWindow

from cet4_app.ui.widgets.chart_widgets import BarChartWidget, LineChartWidget


@pytest.fixture
def main_window(qtbot):
    """Create a main window for hosting chart widgets."""
    window = QMainWindow()
    window.resize(800, 600)
    window.show()
    qtbot.addWidget(window)
    return window


class TestLineChartWidget:
    """Tests for LineChartWidget."""

    @pytest.fixture
    def chart(self, main_window, qtbot):
        widget = LineChartWidget(title="正确率趋势", parent=main_window)
        qtbot.addWidget(widget)
        return widget

    def test_initial_state_no_data(self, chart: LineChartWidget):
        """Chart shows placeholder when no data is set."""
        assert not chart._has_data
        assert not chart._placeholder.isHidden()
        assert chart._chart_view.isHidden()

    def test_set_data_shows_chart(self, chart: LineChartWidget):
        """Setting data shows the chart and hides placeholder."""
        data = {
            "Listening": [(1, 60.0), (2, 70.0), (3, 75.0)],
            "Reading": [(1, 55.0), (2, 65.0), (3, 80.0)],
        }
        chart.set_data(data)
        assert chart._has_data
        assert not chart._chart_view.isHidden()
        assert chart._placeholder.isHidden()

    def test_set_empty_data_shows_placeholder(self, chart: LineChartWidget):
        """Setting empty data shows placeholder."""
        chart.set_data({})
        assert not chart._has_data
        assert not chart._placeholder.isHidden()

    def test_set_data_with_empty_series(self, chart: LineChartWidget):
        """Setting data with all empty series shows placeholder."""
        chart.set_data({"Listening": [], "Reading": []})
        assert not chart._has_data

    def test_export_buttons_hidden_without_data(self, chart: LineChartWidget):
        """Export buttons are hidden when there's no data."""
        assert chart._export_png_btn.isHidden()
        assert chart._export_csv_btn.isHidden()

    def test_export_buttons_visible_with_data(self, chart: LineChartWidget):
        """Export buttons are visible when data is present."""
        chart.set_data({"Test": [(1, 50.0)]})
        assert not chart._export_png_btn.isHidden()
        assert not chart._export_csv_btn.isHidden()

    def test_export_png_to_path(self, chart: LineChartWidget):
        """Programmatic PNG export works."""
        chart.set_data({"Test": [(1, 50.0), (2, 60.0)]})
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            path = f.name
        result = chart.export_png_to_path(path)
        assert result is True
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0
        Path(path).unlink()

    def test_export_csv_to_path(self, chart: LineChartWidget):
        """Programmatic CSV export produces correct data."""
        data = {
            "Listening": [(1, 60.0), (2, 70.0)],
            "Reading": [(1, 55.0), (2, 80.0)],
        }
        chart.set_data(data)
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            path = f.name
        result = chart.export_csv_to_path(path)
        assert result is True

        content = Path(path).read_text(encoding="utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Header
        assert rows[0] == ["序号", "Listening", "Reading"]
        # Data rows
        assert rows[1][0] == "1"
        assert rows[2][0] == "2"
        Path(path).unlink()

    def test_csv_data_content(self, chart: LineChartWidget):
        """CSV data contains correct values."""
        data = {"Series A": [(1, 45.5), (2, 67.3)]}
        chart.set_data(data)
        csv_str = chart._get_csv_data()
        reader = csv.reader(io.StringIO(csv_str))
        rows = list(reader)
        assert rows[0] == ["序号", "Series A"]
        assert rows[1] == ["1", "45.5"]
        assert rows[2] == ["2", "67.3"]

    def test_multiple_set_data_calls(self, chart: LineChartWidget):
        """Calling set_data multiple times replaces previous data."""
        chart.set_data({"A": [(1, 50.0)]})
        assert chart._has_data
        chart.set_data({"B": [(1, 60.0), (2, 70.0)]})
        assert chart._has_data
        csv_str = chart._get_csv_data()
        assert "B" in csv_str
        assert "A" not in csv_str


class TestBarChartWidget:
    """Tests for BarChartWidget."""

    @pytest.fixture
    def chart(self, main_window, qtbot):
        widget = BarChartWidget(title="错题统计", parent=main_window)
        qtbot.addWidget(widget)
        return widget

    def test_initial_state_no_data(self, chart: BarChartWidget):
        """Chart shows placeholder when no data is set."""
        assert not chart._has_data
        assert not chart._placeholder.isHidden()

    def test_set_data_shows_chart(self, chart: BarChartWidget):
        """Setting data shows the chart."""
        categories = ["2024-01-01", "2024-01-02", "2024-01-03"]
        bar_data = {
            "新增错题": [5, 3, 7],
            "复习通过": [2, 4, 1],
        }
        chart.set_data(categories, bar_data, x_label="日期", y_label="题数")
        assert chart._has_data
        assert not chart._chart_view.isHidden()
        assert chart._placeholder.isHidden()

    def test_set_empty_categories_shows_placeholder(self, chart: BarChartWidget):
        """Empty categories shows placeholder."""
        chart.set_data([], {"A": [1, 2]})
        assert not chart._has_data

    def test_set_empty_bar_data_shows_placeholder(self, chart: BarChartWidget):
        """Empty bar data shows placeholder."""
        chart.set_data(["cat1"], {})
        assert not chart._has_data

    def test_export_png_to_path(self, chart: BarChartWidget):
        """Programmatic PNG export works."""
        chart.set_data(["A", "B"], {"Values": [10, 20]})
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            path = f.name
        result = chart.export_png_to_path(path)
        assert result is True
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0
        Path(path).unlink()

    def test_export_csv_to_path(self, chart: BarChartWidget):
        """Programmatic CSV export produces correct data."""
        categories = ["听力", "阅读", "写作"]
        bar_data = {"平均耗时(秒)": [45, 120, 300]}
        chart.set_data(categories, bar_data, y_label="秒")

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            path = f.name
        result = chart.export_csv_to_path(path)
        assert result is True

        content = Path(path).read_text(encoding="utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        assert rows[0] == ["类别", "平均耗时(秒)"]
        assert rows[1] == ["听力", "45"]
        assert rows[2] == ["阅读", "120"]
        assert rows[3] == ["写作", "300"]
        Path(path).unlink()

    def test_csv_data_content(self, chart: BarChartWidget):
        """CSV data contains correct values."""
        chart.set_data(["Day1", "Day2"], {"New": [3, 5], "Pass": [1, 2]})
        csv_str = chart._get_csv_data()
        reader = csv.reader(io.StringIO(csv_str))
        rows = list(reader)
        assert rows[0] == ["类别", "New", "Pass"]
        assert rows[1] == ["Day1", "3", "1"]
        assert rows[2] == ["Day2", "5", "2"]

    def test_export_failed_signal(self, chart: BarChartWidget, qtbot):
        """Export to invalid path returns False (programmatic export)."""
        chart.set_data(["A"], {"V": [1]})
        # Programmatic export to invalid path returns False
        result = chart.export_csv_to_path("Z:\\nonexistent\\path\\that\\cannot\\exist\\file.csv")
        assert result is False

    def test_multiple_bar_sets(self, chart: BarChartWidget):
        """Multiple bar sets are rendered correctly."""
        categories = ["Mon", "Tue", "Wed"]
        bar_data = {
            "Series A": [10, 20, 30],
            "Series B": [5, 15, 25],
            "Series C": [8, 12, 18],
        }
        chart.set_data(categories, bar_data)
        assert chart._has_data
        csv_str = chart._get_csv_data()
        assert "Series A" in csv_str
        assert "Series B" in csv_str
        assert "Series C" in csv_str
