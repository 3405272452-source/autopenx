"""Unit tests for AudioPlayerWidget.

Tests cover:
- Widget construction and initial state
- Embedded-in-paper disables all controls (Requirement 5.6)
- Speed cycling through 0.75x, 1.0x, 1.25x, 1.5x (Requirement 5.3)
- AB loop activation and rejection (Requirement 5.4)
- Locate button with fallback (Requirement 5.5)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from PySide6.QtMultimedia import QMediaPlayer

from cet4_app.domain.enums import AudioStatus
from cet4_app.ui.widgets.audio_player_widget import AudioPlayerWidget


@pytest.fixture
def widget(qtbot):
    """Create an AudioPlayerWidget for testing."""
    w = AudioPlayerWidget()
    qtbot.addWidget(w)
    return w


class TestConstruction:
    """Test widget initial state."""

    def test_initial_state(self, widget: AudioPlayerWidget):
        assert widget._rate_index == 1  # 1.0x default
        assert widget._a_point_ms is None
        assert widget._b_point_ms is None
        assert widget._ab_loop_active is False
        assert widget._duration_ms == 0

    def test_play_button_shows_play_icon(self, widget: AudioPlayerWidget):
        assert widget._btn_play.text() == "▶"

    def test_speed_button_shows_1x(self, widget: AudioPlayerWidget):
        assert widget._btn_speed.text() == "1.0×"


class TestEmbeddedInPaper:
    """Requirement 5.6: embedded-in-paper disables all controls."""

    def test_disables_all_controls(self, widget: AudioPlayerWidget):
        widget.load_audio("", AudioStatus.embedded_in_paper)

        # All interactive controls should be disabled
        for ctrl in widget._controls:
            assert not ctrl.isEnabled(), f"{ctrl.objectName() or ctrl.text()} should be disabled"

    def test_shows_embedded_message(self, widget: AudioPlayerWidget):
        widget.load_audio("", AudioStatus.embedded_in_paper)
        # Use isVisibleTo(parent) since the top-level widget is not shown
        assert widget._embedded_label.isVisibleTo(widget)
        assert "真题 PDF" in widget._embedded_label.text()

    def test_time_labels_show_placeholder(self, widget: AudioPlayerWidget):
        widget.load_audio("", AudioStatus.embedded_in_paper)
        assert widget._time_label.text() == "--:--"
        assert widget._duration_label.text() == "--:--"


class TestSpeedCycling:
    """Requirement 5.3: 0.75x, 1.0x, 1.25x, 1.5x speed switching."""

    def test_cycles_through_all_rates(self, widget: AudioPlayerWidget):
        expected_rates = ["1.25×", "1.5×", "0.75×", "1.0×"]
        for expected in expected_rates:
            widget._cycle_speed()
            assert widget._btn_speed.text() == expected

    def test_playback_rate_property(self, widget: AudioPlayerWidget):
        assert widget.playback_rate == 1.0
        widget._cycle_speed()
        assert widget.playback_rate == 1.25
        widget._cycle_speed()
        assert widget.playback_rate == 1.5
        widget._cycle_speed()
        assert widget.playback_rate == 0.75
        widget._cycle_speed()
        assert widget.playback_rate == 1.0


class TestABLoop:
    """Requirement 5.4: AB loop marking."""

    def test_set_a_point(self, widget: AudioPlayerWidget):
        # Simulate player at position 5000ms
        widget._player.setPosition = lambda x: None  # no-op
        with patch.object(widget._player, "position", return_value=5000):
            widget._set_a_point()
        assert widget._a_point_ms == 5000

    def test_ab_loop_activates_when_b_after_a(self, widget: AudioPlayerWidget):
        widget._a_point_ms = 2000  # A at 2s
        with patch.object(widget._player, "position", return_value=5000):
            widget._set_b_point()
        assert widget._b_point_ms == 5000
        assert widget._ab_loop_active is True
        assert widget._btn_clear_ab.isEnabled()

    def test_ab_loop_rejected_when_b_before_a(self, widget: AudioPlayerWidget):
        widget._a_point_ms = 5000  # A at 5s
        with patch.object(widget._player, "position", return_value=2000):
            widget._set_b_point()
        # B point should be rejected
        assert widget._b_point_ms is None
        assert widget._ab_loop_active is False
        assert "B 点必须晚于 A 点" in widget._status_label.text()

    def test_clear_ab_loop(self, widget: AudioPlayerWidget):
        widget._a_point_ms = 2000
        widget._b_point_ms = 5000
        widget._ab_loop_active = True
        widget._btn_clear_ab.setEnabled(True)

        widget._clear_ab_loop()

        assert widget._a_point_ms is None
        assert widget._b_point_ms is None
        assert widget._ab_loop_active is False
        assert not widget._btn_clear_ab.isEnabled()

    def test_position_loops_back_at_b_point(self, widget: AudioPlayerWidget):
        """When AB loop is active and position reaches B, it should loop to A."""
        widget._a_point_ms = 2000
        widget._b_point_ms = 5000
        widget._ab_loop_active = True
        widget._duration_ms = 10000
        widget._seek_slider.setRange(0, 10000)

        # Track if setPosition was called with A point
        positions_set: list[int] = []
        widget._player.setPosition = lambda pos: positions_set.append(pos)

        # Simulate position reaching B point
        widget._on_position_changed(5000)

        assert 2000 in positions_set

    def test_position_does_not_loop_before_b_point(self, widget: AudioPlayerWidget):
        """When AB loop is active but position is before B, no jump occurs."""
        widget._a_point_ms = 2000
        widget._b_point_ms = 5000
        widget._ab_loop_active = True
        widget._duration_ms = 10000
        widget._seek_slider.setRange(0, 10000)

        positions_set: list[int] = []
        widget._player.setPosition = lambda pos: positions_set.append(pos)

        # Simulate position before B point
        widget._on_position_changed(3000)

        # No jump should occur
        assert len(positions_set) == 0

    def test_position_loops_back_past_b_point(self, widget: AudioPlayerWidget):
        """When position overshoots B point, it should still loop to A."""
        widget._a_point_ms = 2000
        widget._b_point_ms = 5000
        widget._ab_loop_active = True
        widget._duration_ms = 10000
        widget._seek_slider.setRange(0, 10000)

        positions_set: list[int] = []
        widget._player.setPosition = lambda pos: positions_set.append(pos)

        # Simulate position past B point (overshoot)
        widget._on_position_changed(5500)

        assert 2000 in positions_set

    def test_no_loop_when_ab_inactive(self, widget: AudioPlayerWidget):
        """When AB loop is not active, position at B does not trigger jump."""
        widget._a_point_ms = 2000
        widget._b_point_ms = 5000
        widget._ab_loop_active = False  # Loop not active
        widget._duration_ms = 10000
        widget._seek_slider.setRange(0, 10000)

        positions_set: list[int] = []
        widget._player.setPosition = lambda pos: positions_set.append(pos)

        widget._on_position_changed(5000)

        assert len(positions_set) == 0


class TestLocate:
    """Requirement 5.5: Locate to question audio."""

    def test_locate_disabled_when_no_question(self, widget: AudioPlayerWidget):
        widget.set_question_for_locate(None)
        assert not widget._btn_locate.isEnabled()

    def test_locate_precise_when_audio_range_available(self, qtbot, widget: AudioPlayerWidget):
        """Req 5.5: When question has audio_range, seek to its start time."""
        from cet4_app.domain.models.question import AudioRange, Question

        q = Question.model_construct(
            id="test-q2",
            paper_id="test-paper",
            section="listening",
            sub_section="news",
            question_type="listening_news",
            prompt="Test question with audio range",
            options=["A", "B", "C", "D"],
            reference_answer="B",
            explanation="",
            score=7.1,
            tags=[],
            audio_range=AudioRange(start_s=45.0, end_s=60.0),
        )

        widget.set_question_for_locate(q, fallback_group_start_s=10.0)
        widget._duration_ms = 120000  # 120s total

        # Track seek position
        positions_set: list[int] = []
        widget._player.setPosition = lambda pos: positions_set.append(pos)

        widget._on_locate_clicked()

        # Should seek to 45s = 45000ms
        assert 45000 in positions_set
        # No fallback message should be shown
        assert widget._status_label.text() == ""

    def test_locate_emits_fallback_message(self, qtbot, widget: AudioPlayerWidget):
        """When question has no audio_range, fallback message is emitted."""
        from cet4_app.domain.models.question import Question

        # Create a minimal question without audio_range
        q = Question.model_construct(
            id="test-q1",
            paper_id="test-paper",
            section="listening",
            sub_section="news",
            question_type="listening_news",
            prompt="Test question",
            options=["A", "B", "C", "D"],
            reference_answer="A",
            explanation="",
            score=7.1,
            tags=[],
            audio_range=None,
        )

        widget.set_question_for_locate(q, fallback_group_start_s=10.0)
        widget._duration_ms = 60000  # 60s total

        with qtbot.waitSignal(widget.locate_fallback_message, timeout=1000):
            widget._on_locate_clicked()

    def test_locate_fallback_seeks_to_group_start(self, qtbot, widget: AudioPlayerWidget):
        """Req 5.5: Fallback seeks to group start time."""
        from cet4_app.domain.models.question import Question

        q = Question.model_construct(
            id="test-q3",
            paper_id="test-paper",
            section="listening",
            sub_section="conversation",
            question_type="listening_conversation",
            prompt="Test question no range",
            options=["A", "B", "C", "D"],
            reference_answer="C",
            explanation="",
            score=7.1,
            tags=[],
            audio_range=None,
        )

        widget.set_question_for_locate(q, fallback_group_start_s=25.5)
        widget._duration_ms = 120000  # 120s total

        positions_set: list[int] = []
        widget._player.setPosition = lambda pos: positions_set.append(pos)

        widget._on_locate_clicked()

        # Should seek to fallback group start: 25.5s = 25500ms
        assert 25500 in positions_set
        # Fallback message should be displayed
        assert "精确区段不可用" in widget._status_label.text()
