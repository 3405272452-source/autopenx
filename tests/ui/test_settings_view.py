"""Tests for SettingsView — application settings page.

Requirements: 1.2, 1.3, 12.3, 12.4, 12.5, 14.5, 15.2, 15.10
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from PySide6.QtWidgets import QMessageBox

from cet4_app.ui.views.settings_view import SettingsView


@pytest.fixture()
def view(qtbot):
    """Create a SettingsView for testing."""
    v = SettingsView()
    qtbot.addWidget(v)
    v.show()
    return v


class TestSettingsViewLibraryRoot:
    """Tests for Library Root path configuration."""

    def test_set_library_root(self, view: SettingsView):
        """set_library_root populates the path field."""
        view.set_library_root(r"C:\Users\test\cet4")
        assert view.get_library_root() == r"C:\Users\test\cet4"

    def test_get_library_root_strips_whitespace(self, view: SettingsView):
        """get_library_root strips leading/trailing whitespace."""
        view._library_root_edit.setText("  /some/path  ")
        assert view.get_library_root() == "/some/path"

    def test_set_library_root_error_shows_message(self, view: SettingsView):
        """set_library_root_error displays error text."""
        view.set_library_root_error("路径不存在")
        assert view._library_root_error_label.isVisible()
        assert "路径不存在" in view._library_root_error_label.text()

    def test_set_library_root_clears_error(self, view: SettingsView):
        """Setting a new library root hides the error label."""
        view.set_library_root_error("some error")
        assert view._library_root_error_label.isVisible()
        view.set_library_root(r"C:\new\path")
        assert not view._library_root_error_label.isVisible()

    def test_library_root_changed_signal_on_save(self, view: SettingsView, qtbot):
        """Saving with a non-empty path emits library_root_changed."""
        view.set_library_root(r"D:\my_library")
        with qtbot.waitSignal(view.library_root_changed, timeout=1000) as blocker:
            view._on_save()
        assert blocker.args == [r"D:\my_library"]


class TestSettingsViewDeepSeek:
    """Tests for DeepSeek API configuration."""

    def test_default_values(self, view: SettingsView):
        """Default DeepSeek field values match Req 15.2 defaults."""
        assert view.get_model() == "deepseek-v4-flash"
        assert view.get_temperature() == 0.3
        assert view.get_max_output_tokens() == 1024
        assert view.get_request_timeout() == 60

    def test_set_deepseek_settings(self, view: SettingsView):
        """set_deepseek_settings populates all fields."""
        view.set_deepseek_settings(
            api_key_masked="sk-****abcd",
            model="deepseek-chat",
            temperature=0.7,
            max_output_tokens=2048,
            request_timeout=30,
        )
        assert view.get_model() == "deepseek-chat"
        assert view.get_temperature() == 0.7
        assert view.get_max_output_tokens() == 2048
        assert view.get_request_timeout() == 30

    def test_api_key_masked_input(self, view: SettingsView):
        """API key field uses password echo mode."""
        assert view._api_key_edit.echoMode() == view._api_key_edit.EchoMode.Password

    def test_get_api_key_input_empty_by_default(self, view: SettingsView):
        """API key input is empty when user hasn't typed anything."""
        assert view.get_api_key_input() == ""

    def test_get_api_key_input_returns_typed_text(self, view: SettingsView):
        """get_api_key_input returns what the user typed."""
        view._api_key_edit.setText("sk-test1234567890abcdef")
        assert view.get_api_key_input() == "sk-test1234567890abcdef"

    def test_temperature_range(self, view: SettingsView):
        """Temperature spin box enforces 0.0–1.5 range."""
        assert view._temperature_spin.minimum() == 0.0
        assert view._temperature_spin.maximum() == 1.5

    def test_max_tokens_range(self, view: SettingsView):
        """Max tokens spin box enforces 256–4096 range."""
        assert view._max_tokens_spin.minimum() == 256
        assert view._max_tokens_spin.maximum() == 4096

    def test_timeout_range(self, view: SettingsView):
        """Timeout spin box enforces 5–120 range."""
        assert view._timeout_spin.minimum() == 5
        assert view._timeout_spin.maximum() == 120


class TestSettingsViewAIStatus:
    """Tests for AI-enabled status indicator (Req 15.10)."""

    def test_ai_disabled_shows_warning(self, view: SettingsView):
        """When AI is disabled, status label shows warning."""
        view.set_ai_enabled(False)
        text = view._ai_status_label.text()
        assert "禁用" in text or "API Key" in text

    def test_ai_enabled_shows_success(self, view: SettingsView):
        """When AI is enabled, status label shows success."""
        view.set_ai_enabled(True)
        text = view._ai_status_label.text()
        assert "启用" in text

    def test_ai_enabled_changed_signal_on_save(self, view: SettingsView, qtbot):
        """Saving emits ai_enabled_changed signal."""
        view._api_key_edit.setText("sk-valid-key-1234567890")
        with qtbot.waitSignal(view.ai_enabled_changed, timeout=1000) as blocker:
            view._on_save()
        assert blocker.args == [True]

    def test_ai_disabled_signal_when_no_key(self, view: SettingsView, qtbot):
        """Saving with empty key emits ai_enabled_changed(False)."""
        view._api_key_edit.clear()
        with qtbot.waitSignal(view.ai_enabled_changed, timeout=1000) as blocker:
            view._on_save()
        assert blocker.args == [False]


class TestSettingsViewLogs:
    """Tests for log management buttons (Req 14.5)."""

    def test_view_logs_signal(self, view: SettingsView, qtbot):
        """Clicking view logs emits view_logs_requested."""
        with qtbot.waitSignal(view.view_logs_requested, timeout=1000):
            view._on_view_logs()

    def test_clear_logs_with_confirmation(self, view: SettingsView, qtbot):
        """Clear logs emits signal only after user confirms."""
        with patch(
            "cet4_app.ui.views.settings_view.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ):
            with qtbot.waitSignal(view.clear_logs_requested, timeout=1000):
                view._on_clear_logs()

    def test_clear_logs_cancelled(self, view: SettingsView, qtbot):
        """Clear logs does NOT emit signal when user cancels."""
        with patch(
            "cet4_app.ui.views.settings_view.QMessageBox.question",
            return_value=QMessageBox.StandardButton.No,
        ):
            with qtbot.assertNotEmitted(view.clear_logs_requested):
                view._on_clear_logs()


class TestSettingsViewBackup:
    """Tests for backup import/export (Req 12.3, 12.4, 12.5)."""

    def test_export_with_confirmation(self, view: SettingsView, qtbot):
        """Export emits signal after user confirms."""
        with patch(
            "cet4_app.ui.views.settings_view.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ):
            with qtbot.waitSignal(view.export_requested, timeout=1000):
                view._on_export_backup()

    def test_export_cancelled(self, view: SettingsView, qtbot):
        """Export does NOT emit signal when user cancels."""
        with patch(
            "cet4_app.ui.views.settings_view.QMessageBox.question",
            return_value=QMessageBox.StandardButton.No,
        ):
            with qtbot.assertNotEmitted(view.export_requested):
                view._on_export_backup()

    def test_import_with_confirmation(self, view: SettingsView, qtbot):
        """Import emits signal with file path after user confirms."""
        with patch(
            "cet4_app.ui.views.settings_view.QFileDialog.getOpenFileName",
            return_value=("/tmp/backup.json", "JSON 文件 (*.json)"),
        ):
            with patch(
                "cet4_app.ui.views.settings_view.QMessageBox.warning",
                return_value=QMessageBox.StandardButton.Yes,
            ):
                with qtbot.waitSignal(
                    view.import_requested, timeout=1000
                ) as blocker:
                    view._on_import_backup()
        assert blocker.args == ["/tmp/backup.json"]

    def test_import_cancelled_at_file_dialog(self, view: SettingsView, qtbot):
        """Import does NOT emit signal when file dialog is cancelled."""
        with patch(
            "cet4_app.ui.views.settings_view.QFileDialog.getOpenFileName",
            return_value=("", ""),
        ):
            with qtbot.assertNotEmitted(view.import_requested):
                view._on_import_backup()

    def test_import_cancelled_at_confirmation(self, view: SettingsView, qtbot):
        """Import does NOT emit signal when confirmation is rejected."""
        with patch(
            "cet4_app.ui.views.settings_view.QFileDialog.getOpenFileName",
            return_value=("/tmp/backup.json", "JSON 文件 (*.json)"),
        ):
            with patch(
                "cet4_app.ui.views.settings_view.QMessageBox.warning",
                return_value=QMessageBox.StandardButton.No,
            ):
                with qtbot.assertNotEmitted(view.import_requested):
                    view._on_import_backup()


class TestSettingsViewSaveCancel:
    """Tests for Save/Cancel buttons."""

    def test_settings_saved_signal(self, view: SettingsView, qtbot):
        """Save button emits settings_saved signal."""
        with qtbot.waitSignal(view.settings_saved, timeout=1000):
            view._on_save()

    def test_cancel_hides_error(self, view: SettingsView):
        """Cancel hides the library root error label."""
        view.set_library_root_error("test error")
        assert view._library_root_error_label.isVisible()
        view._on_cancel()
        assert not view._library_root_error_label.isVisible()
