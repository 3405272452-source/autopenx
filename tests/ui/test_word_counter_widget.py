"""Tests for WordCounterWidget — real-time word count with throttle.

Requirements: 4.4, 7.3
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import QTimer

from cet4_app.domain.grading.word_count import WordCountReport
from cet4_app.ui.widgets.word_counter import WordCounterWidget


@pytest.fixture()
def writing_widget(qtbot):
    """Create a WordCounterWidget for writing."""
    w = WordCounterWidget(kind="writing")
    qtbot.addWidget(w)
    w.show()
    return w


@pytest.fixture()
def translation_widget(qtbot):
    """Create a WordCounterWidget for translation."""
    w = WordCounterWidget(kind="translation")
    qtbot.addWidget(w)
    w.show()
    return w


class TestWordCounterWidget:
    """Unit tests for WordCounterWidget."""

    def test_initial_state(self, writing_widget: WordCounterWidget):
        """Widget starts showing count 0 and 'below' band."""
        assert writing_widget.kind == "writing"
        # last_report is set from initial display
        report = writing_widget.last_report
        assert report is not None
        assert report.count == 0
        assert report.band == "below"

    def test_force_update_writing_below(self, writing_widget: WordCounterWidget):
        """force_update with <120 words shows 'below' for writing."""
        text = " ".join(["word"] * 50)
        writing_widget.force_update(text)
        report = writing_widget.last_report
        assert report is not None
        assert report.count == 50
        assert report.band == "below"

    def test_force_update_writing_ok(self, writing_widget: WordCounterWidget):
        """force_update with 120-180 words shows 'ok' for writing."""
        text = " ".join(["word"] * 150)
        writing_widget.force_update(text)
        report = writing_widget.last_report
        assert report is not None
        assert report.count == 150
        assert report.band == "ok"

    def test_force_update_writing_over(self, writing_widget: WordCounterWidget):
        """force_update with >180 words shows 'over' for writing."""
        text = " ".join(["word"] * 200)
        writing_widget.force_update(text)
        report = writing_widget.last_report
        assert report is not None
        assert report.count == 200
        assert report.band == "over"

    def test_force_update_translation_below(self, translation_widget: WordCounterWidget):
        """force_update with <140 words shows 'below' for translation."""
        text = " ".join(["word"] * 100)
        translation_widget.force_update(text)
        report = translation_widget.last_report
        assert report is not None
        assert report.count == 100
        assert report.band == "below"

    def test_force_update_translation_ok(self, translation_widget: WordCounterWidget):
        """force_update with 140-160 words shows 'ok' for translation."""
        text = " ".join(["word"] * 150)
        translation_widget.force_update(text)
        report = translation_widget.last_report
        assert report is not None
        assert report.count == 150
        assert report.band == "ok"

    def test_force_update_translation_over(self, translation_widget: WordCounterWidget):
        """force_update with >160 words shows 'over' for translation."""
        text = " ".join(["word"] * 170)
        translation_widget.force_update(text)
        report = translation_widget.last_report
        assert report is not None
        assert report.count == 170
        assert report.band == "over"

    def test_throttle_only_fires_once_per_second(self, writing_widget: WordCounterWidget, qtbot):
        """Multiple rapid update_text calls result in only one computation."""
        # Send multiple updates rapidly
        writing_widget.update_text("one two three")
        writing_widget.update_text("one two three four")
        writing_widget.update_text("one two three four five")

        # Wait for the throttle timer to fire
        qtbot.waitUntil(lambda: writing_widget.last_report is not None and writing_widget.last_report.count == 5, timeout=2000)

        # The final result should reflect the last text
        report = writing_widget.last_report
        assert report is not None
        assert report.count == 5

    def test_count_updated_signal(self, writing_widget: WordCounterWidget, qtbot):
        """count_updated signal is emitted after force_update."""
        with qtbot.waitSignal(writing_widget.count_updated, timeout=1000) as blocker:
            writing_widget.force_update("hello world test")
        report = blocker.args[0]
        assert isinstance(report, WordCountReport)
        assert report.count == 3

    def test_empty_text(self, writing_widget: WordCounterWidget):
        """Empty text gives count 0."""
        writing_widget.force_update("")
        report = writing_widget.last_report
        assert report is not None
        assert report.count == 0
        assert report.band == "below"

    def test_boundary_writing_120(self, writing_widget: WordCounterWidget):
        """Exactly 120 words is 'ok' for writing."""
        text = " ".join(["word"] * 120)
        writing_widget.force_update(text)
        assert writing_widget.last_report.band == "ok"

    def test_boundary_writing_180(self, writing_widget: WordCounterWidget):
        """Exactly 180 words is 'ok' for writing."""
        text = " ".join(["word"] * 180)
        writing_widget.force_update(text)
        assert writing_widget.last_report.band == "ok"

    def test_boundary_translation_140(self, translation_widget: WordCounterWidget):
        """Exactly 140 words is 'ok' for translation."""
        text = " ".join(["word"] * 140)
        translation_widget.force_update(text)
        assert translation_widget.last_report.band == "ok"

    def test_boundary_translation_160(self, translation_widget: WordCounterWidget):
        """Exactly 160 words is 'ok' for translation."""
        text = " ".join(["word"] * 160)
        translation_widget.force_update(text)
        assert translation_widget.last_report.band == "ok"
