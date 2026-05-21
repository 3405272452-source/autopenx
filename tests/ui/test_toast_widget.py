"""Tests for the ToastWidget — non-blocking bottom toast notification."""

from __future__ import annotations

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QMainWindow

from cet4_app.ui.widgets.toast import ToastSeverity, ToastWidget


@pytest.fixture
def main_window(qtbot):
    """Create a main window with a toast widget."""
    window = QMainWindow()
    window.resize(800, 600)
    window.show()
    qtbot.addWidget(window)
    return window


@pytest.fixture
def toast(main_window, qtbot):
    """Create a toast widget attached to the main window."""
    t = ToastWidget(parent=main_window, timeout_ms=0)  # No auto-dismiss for tests
    qtbot.addWidget(t)
    return t


class TestToastWidget:
    """Tests for ToastWidget functionality."""

    def test_initial_state_hidden(self, toast: ToastWidget):
        """Toast should be hidden initially."""
        assert not toast.is_visible

    def test_show_info_toast(self, toast: ToastWidget):
        """Showing an info toast makes it visible."""
        toast.show_toast("Test message", ToastSeverity.info)
        assert toast.is_visible

    def test_show_warning_toast(self, toast: ToastWidget):
        """Showing a warning toast makes it visible."""
        toast.show_toast("Warning!", ToastSeverity.warning)
        assert toast.is_visible

    def test_show_error_toast(self, toast: ToastWidget):
        """Showing an error toast makes it visible."""
        toast.show_toast("Error occurred", ToastSeverity.error)
        assert toast.is_visible

    def test_dismiss_hides_toast(self, toast: ToastWidget):
        """Dismissing the toast hides it."""
        toast.show_toast("Test")
        assert toast.is_visible
        toast.dismiss()
        assert not toast.is_visible

    def test_dismiss_emits_signal(self, toast: ToastWidget, qtbot):
        """Dismissing emits the dismissed signal."""
        toast.show_toast("Test")
        with qtbot.waitSignal(toast.dismissed, timeout=1000):
            toast.dismiss()

    def test_expand_detail(self, toast: ToastWidget):
        """Expanding shows the detail area."""
        toast.show_toast("Error", ToastSeverity.error, detail="Full log content here")
        assert not toast.is_expanded
        toast._toggle_expand()
        assert toast.is_expanded

    def test_collapse_detail(self, toast: ToastWidget):
        """Collapsing hides the detail area."""
        toast.show_toast("Error", ToastSeverity.error, detail="Full log content")
        toast._toggle_expand()
        assert toast.is_expanded
        toast._toggle_expand()
        assert not toast.is_expanded

    def test_no_expand_button_without_detail(self, toast: ToastWidget):
        """Expand button is hidden when no detail is provided."""
        toast.show_toast("Simple message")
        assert not toast._expand_btn.isVisible()

    def test_expand_button_visible_with_detail(self, toast: ToastWidget):
        """Expand button is visible when detail is provided."""
        toast.show_toast("Error", detail="Some detail text")
        assert toast._expand_btn.isVisible()

    def test_auto_dismiss(self, main_window, qtbot):
        """Toast auto-dismisses after timeout."""
        toast = ToastWidget(parent=main_window, timeout_ms=100)
        qtbot.addWidget(toast)
        toast.show_toast("Auto dismiss test")
        assert toast.is_visible
        with qtbot.waitSignal(toast.dismissed, timeout=500):
            pass
        assert not toast.is_visible

    def test_message_text_set(self, toast: ToastWidget):
        """Message label text is set correctly."""
        toast.show_toast("Hello World", ToastSeverity.info)
        assert toast._message_label.text() == "Hello World"

    def test_detail_text_set(self, toast: ToastWidget):
        """Detail area text is set correctly."""
        detail = "Detailed error log\nLine 2\nLine 3"
        toast.show_toast("Error", detail=detail)
        assert toast._detail_area.toPlainText() == detail

    def test_severity_enum_values(self):
        """ToastSeverity enum has expected values."""
        assert ToastSeverity.info == "info"
        assert ToastSeverity.warning == "warning"
        assert ToastSeverity.error == "error"
