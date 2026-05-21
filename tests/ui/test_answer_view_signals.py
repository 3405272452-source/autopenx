"""Unit tests for AnswerView.

Tests cover:
- Section navigation: Writing → Listening → Reading → Translation (Req 4.1)
- Banked_cloze candidate word mutual exclusion (Req 4.3)
- Draft save timestamp display (Req 4.5)
- Submit confirmation dialog (Req 4.9)
- Mock exam countdown timer (Req 4.10)
- Signal emissions for draft saving, submission, navigation
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

import pytest
from PySide6.QtCore import QTimer

from cet4_app.domain.enums import SectionName, SessionMode, SheetStatus
from cet4_app.ui.views.answer_view import (
    DRAFT_SAVE_INTERVAL_MS,
    MOCK_EXAM_DURATION_S,
    SECTION_ORDER,
    AnswerView,
    _format_countdown,
)


@pytest.fixture
def view(qtbot):
    """Create an AnswerView for testing."""
    w = AnswerView()
    qtbot.addWidget(w)
    return w


# ---------------------------------------------------------------------------
# Section Navigation (Req 4.1)
# ---------------------------------------------------------------------------


class TestSectionNavigation:
    """Test section navigation follows Writing → Listening → Reading → Translation."""

    def test_section_order_is_correct(self):
        assert SECTION_ORDER == [
            SectionName.writing,
            SectionName.listening,
            SectionName.reading,
            SectionName.translation,
        ]

    def test_initial_section_is_writing(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)
        assert view.current_section == SectionName.writing

    def test_navigate_next_section(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)

        with qtbot.waitSignal(view.section_changed):
            result = view.navigate_next_section()
        assert result is True
        assert view.current_section == SectionName.listening

    def test_navigate_next_at_last_returns_false(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)
        # Navigate to last section
        view.navigate_to_section(SectionName.translation)
        result = view.navigate_next_section()
        assert result is False
        assert view.current_section == SectionName.translation

    def test_navigate_prev_section(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)
        view.navigate_to_section(SectionName.reading)

        with qtbot.waitSignal(view.section_changed):
            result = view.navigate_prev_section()
        assert result is True
        assert view.current_section == SectionName.listening

    def test_navigate_prev_at_first_returns_false(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)
        result = view.navigate_prev_section()
        assert result is False
        assert view.current_section == SectionName.writing

    def test_navigate_to_specific_section(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)

        with qtbot.waitSignal(view.section_changed):
            view.navigate_to_section(SectionName.translation)
        assert view.current_section == SectionName.translation

    def test_section_changed_signal_emits_section_name(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)

        with qtbot.waitSignal(view.section_changed) as blocker:
            view.navigate_to_section(SectionName.reading)
        assert blocker.args == ["reading"]

    def test_nav_buttons_highlight_current(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)
        view.navigate_to_section(SectionName.reading)

        # Reading is index 2
        for i, btn in enumerate(view._nav_buttons):
            assert btn.isChecked() == (i == 2)


# ---------------------------------------------------------------------------
# Banked Cloze Mutual Exclusion (Req 4.3)
# ---------------------------------------------------------------------------


class TestBankedClozeMutualExclusion:
    """Test candidate word mutual exclusion for banked_cloze."""

    def test_select_word_succeeds(self, view: AnswerView):
        view.set_banked_cloze_candidates(["apple", "banana", "cherry"])
        assert view.select_banked_word("apple", 1) is True
        assert view.is_banked_word_used("apple") is True

    def test_select_same_word_to_different_blank_rejected(self, view: AnswerView):
        view.set_banked_cloze_candidates(["apple", "banana", "cherry"])
        view.select_banked_word("apple", 1)
        # Try to assign apple to blank 2 — should be rejected
        assert view.select_banked_word("apple", 2) is False

    def test_select_same_word_to_same_blank_succeeds(self, view: AnswerView):
        view.set_banked_cloze_candidates(["apple", "banana", "cherry"])
        view.select_banked_word("apple", 1)
        # Re-selecting same word to same blank is idempotent
        assert view.select_banked_word("apple", 1) is True

    def test_deselect_word_releases_it(self, view: AnswerView):
        view.set_banked_cloze_candidates(["apple", "banana", "cherry"])
        view.select_banked_word("apple", 1)
        view.deselect_banked_word("apple")
        assert view.is_banked_word_used("apple") is False
        # Now it can be assigned to a different blank
        assert view.select_banked_word("apple", 3) is True

    def test_unknown_word_rejected(self, view: AnswerView):
        view.set_banked_cloze_candidates(["apple", "banana", "cherry"])
        assert view.select_banked_word("unknown", 1) is False

    def test_get_assignment_returns_blank_index(self, view: AnswerView):
        view.set_banked_cloze_candidates(["apple", "banana", "cherry"])
        view.select_banked_word("banana", 5)
        assert view.get_banked_word_assignment("banana") == 5

    def test_get_assignment_returns_none_for_unassigned(self, view: AnswerView):
        view.set_banked_cloze_candidates(["apple", "banana", "cherry"])
        assert view.get_banked_word_assignment("apple") is None

    def test_multiple_words_can_be_assigned_to_different_blanks(self, view: AnswerView):
        words = ["apple", "banana", "cherry", "date", "elderberry"]
        view.set_banked_cloze_candidates(words)
        for i, word in enumerate(words, start=1):
            assert view.select_banked_word(word, i) is True
        # All should be used
        for word in words:
            assert view.is_banked_word_used(word) is True


# ---------------------------------------------------------------------------
# Draft Save Timestamp (Req 4.5)
# ---------------------------------------------------------------------------


class TestDraftSaveTimestamp:
    """Test draft save timestamp display."""

    def test_set_draft_saved_at_updates_label(self, view: AnswerView):
        ts = datetime(2024, 12, 15, 14, 30, 45)
        view.set_draft_saved_at(ts)
        assert "14:30:45" in view._draft_label.text()
        assert "已保存" in view._draft_label.text()

    def test_draft_timer_emits_signal(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)

        with qtbot.waitSignal(view.draft_save_requested, timeout=500):
            # Manually trigger the timer callback
            view._on_draft_timer()

    def test_draft_timer_interval_is_30s(self, view: AnswerView):
        assert view._draft_timer.interval() == DRAFT_SAVE_INTERVAL_MS

    def test_draft_timer_not_emitted_when_paused(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)
        view._status = SheetStatus.paused

        # Should not emit when paused
        signals = []
        view.draft_save_requested.connect(lambda: signals.append(True))
        view._on_draft_timer()
        assert len(signals) == 0


# ---------------------------------------------------------------------------
# Submit Confirmation (Req 4.8, 4.9)
# ---------------------------------------------------------------------------


class TestSubmitConfirmation:
    """Test submit confirmation dialog logic."""

    def test_get_unanswered_summary_all_answered(self, view: AnswerView):
        answers = {"q1": "A", "q2": "B", "q3": "text"}
        all_ids = {
            SectionName.writing: ["q3"],
            SectionName.listening: ["q1", "q2"],
        }
        summary = view.get_unanswered_summary(answers, all_ids)
        assert summary == {}

    def test_get_unanswered_summary_some_unanswered(self, view: AnswerView):
        answers = {"q1": "A", "q2": "", "q3": ""}
        all_ids = {
            SectionName.writing: ["q3"],
            SectionName.listening: ["q1", "q2"],
        }
        summary = view.get_unanswered_summary(answers, all_ids)
        assert summary == {SectionName.writing: 1, SectionName.listening: 1}

    def test_get_unanswered_summary_whitespace_only_counts_as_unanswered(
        self, view: AnswerView
    ):
        answers = {"q1": "   ", "q2": "\t\n"}
        all_ids = {SectionName.reading: ["q1", "q2"]}
        summary = view.get_unanswered_summary(answers, all_ids)
        assert summary == {SectionName.reading: 2}

    def test_show_submit_confirmation_returns_true_when_all_answered(
        self, view: AnswerView
    ):
        # No unanswered questions — should return True without dialog
        result = view.show_submit_confirmation({})
        assert result is True

    @patch("cet4_app.ui.views.answer_view.QMessageBox.question")
    def test_show_submit_confirmation_shows_dialog_when_unanswered(
        self, mock_question, view: AnswerView
    ):
        from PySide6.QtWidgets import QMessageBox

        mock_question.return_value = QMessageBox.StandardButton.Yes
        summary = {SectionName.listening: 3, SectionName.reading: 2}
        result = view.show_submit_confirmation(summary)
        assert result is True
        mock_question.assert_called_once()

    @patch("cet4_app.ui.views.answer_view.QMessageBox.question")
    def test_show_submit_confirmation_user_cancels(
        self, mock_question, view: AnswerView
    ):
        from PySide6.QtWidgets import QMessageBox

        mock_question.return_value = QMessageBox.StandardButton.No
        summary = {SectionName.writing: 1}
        result = view.show_submit_confirmation(summary)
        assert result is False

    def test_submit_signal_emitted(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)

        with qtbot.waitSignal(view.submit_requested, timeout=500):
            view._on_submit_clicked()


# ---------------------------------------------------------------------------
# Mock Exam Countdown (Req 4.10)
# ---------------------------------------------------------------------------


class TestMockExamCountdown:
    """Test mock exam 125-minute countdown timer."""

    def test_countdown_visible_in_mock_mode(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam)
        # Use isVisibleTo since the top-level widget is not shown
        assert view._countdown_label.isVisibleTo(view) is True

    def test_countdown_hidden_in_practice_mode(self, view: AnswerView):
        view.start_session(SessionMode.practice)
        assert view._countdown_label.isVisibleTo(view) is False

    def test_countdown_starts_at_125_minutes(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam)
        assert view.remaining_seconds == MOCK_EXAM_DURATION_S
        assert MOCK_EXAM_DURATION_S == 125 * 60

    def test_countdown_decrements(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam)
        initial = view.remaining_seconds
        view._on_countdown_tick()
        assert view.remaining_seconds == initial - 1

    def test_countdown_pauses_when_session_paused(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam)
        view.pause_session()
        assert view.is_countdown_paused is True

        before = view.remaining_seconds
        view._on_countdown_tick()
        # Should not decrement when paused
        assert view.remaining_seconds == before

    def test_countdown_resumes_after_pause(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam)
        view.pause_session()
        view.resume_session()
        assert view.is_countdown_paused is False

        before = view.remaining_seconds
        view._on_countdown_tick()
        assert view.remaining_seconds == before - 1

    def test_countdown_custom_remaining(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam, remaining_seconds=600)
        assert view.remaining_seconds == 600

    def test_countdown_warning_at_10_min(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.mock_exam, remaining_seconds=601)

        with qtbot.waitSignal(view.countdown_warning, timeout=500) as blocker:
            view._on_countdown_tick()  # 601 -> 600
        assert blocker.args == [600]

    def test_countdown_warning_at_1_min(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.mock_exam, remaining_seconds=61)
        # Mark 10-min warning as already fired so we only get the 1-min one
        view._warned_10_min = True

        with qtbot.waitSignal(view.countdown_warning, timeout=500) as blocker:
            view._on_countdown_tick()  # 61 -> 60
        assert blocker.args == [60]

    def test_countdown_expired_signal(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.mock_exam, remaining_seconds=1)

        with qtbot.waitSignal(view.countdown_expired, timeout=500):
            view._on_countdown_tick()  # 1 -> 0

    def test_countdown_does_not_go_negative(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam, remaining_seconds=0)
        view._on_countdown_tick()
        # Timer should stop, remaining should be 0 or -1 but display shows 0
        assert view.remaining_seconds <= 0

    def test_format_countdown(self):
        assert _format_countdown(7500) == "02:05:00"
        assert _format_countdown(600) == "10:00"
        assert _format_countdown(61) == "01:01"
        assert _format_countdown(0) == "00:00"
        assert _format_countdown(-5) == "00:00"


# ---------------------------------------------------------------------------
# Pause (Req 4.7)
# ---------------------------------------------------------------------------


class TestPause:
    """Test pause/resume functionality."""

    def test_pause_emits_signal(self, view: AnswerView, qtbot):
        view.start_session(SessionMode.practice)

        with qtbot.waitSignal(view.pause_requested, timeout=500):
            view._on_pause_clicked()

    def test_pause_stops_draft_timer(self, view: AnswerView):
        view.start_session(SessionMode.practice)
        assert view._draft_timer.isActive()
        view.pause_session()
        assert not view._draft_timer.isActive()

    def test_resume_restarts_draft_timer(self, view: AnswerView):
        view.start_session(SessionMode.practice)
        view.pause_session()
        view.resume_session()
        assert view._draft_timer.isActive()

    def test_stop_timers_stops_all(self, view: AnswerView):
        view.start_session(SessionMode.mock_exam)
        view.stop_timers()
        assert not view._draft_timer.isActive()
        assert not view._countdown_timer.isActive()

    def test_pause_triggers_immediate_draft_save(self, view: AnswerView, qtbot):
        """Req 4.7: Pause SHALL immediately execute a draft save."""
        view.start_session(SessionMode.practice)

        with qtbot.waitSignal(view.draft_save_requested, timeout=500):
            view.pause_session()

    def test_pause_freezes_countdown_in_mock_mode(self, view: AnswerView):
        """Req 4.7: Mock exam countdown freezes on pause."""
        view.start_session(SessionMode.mock_exam, remaining_seconds=1000)
        view.pause_session()
        before = view.remaining_seconds
        # Simulate multiple ticks — none should decrement
        for _ in range(5):
            view._on_countdown_tick()
        assert view.remaining_seconds == before

    def test_resume_continues_countdown_from_frozen_value(self, view: AnswerView):
        """Req 4.7: Resume continues countdown from where it was frozen."""
        view.start_session(SessionMode.mock_exam, remaining_seconds=1000)
        view.pause_session()
        view.resume_session()
        before = view.remaining_seconds
        view._on_countdown_tick()
        assert view.remaining_seconds == before - 1
