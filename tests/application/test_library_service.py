"""Unit tests for application/library_service.py.

Validates:
- Default Library_Root is C:\\Users\\86181\\Desktop\\cet4
- Path validation: rejects non-existent, non-readable, non-directory paths
- On invalid path: preserves original config, returns error with path + reason
- On valid path: updates config, triggers scan, emits ScanResult
- Scan emits results to registered callbacks
- Requirements 1.1, 1.2, 1.3, 1.8
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

from cet4_app.application.library_service import (
    DEFAULT_LIBRARY_ROOT,
    LibraryRootUpdateError,
    LibraryService,
)
from cet4_app.infrastructure.fs.scanner import ScanResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> LibraryService:
    """Create a fresh LibraryService with default config."""
    return LibraryService()


@pytest.fixture
def valid_library_root(tmp_path: Path) -> Path:
    """Create a valid directory that can serve as Library_Root."""
    lib_root = tmp_path / "cet4"
    lib_root.mkdir()
    return lib_root


@pytest.fixture
def populated_library_root(tmp_path: Path) -> Path:
    """Create a Library_Root with the expected exam period directories."""
    lib_root = tmp_path / "cet4"
    lib_root.mkdir()

    # Create the 4 known exam period directories
    dirs = [
        "2023年12月CET4真题+解析+听力音频全3套",
        "2024年6月CET4真题+解析+听力音频全3套",
        "2024年12月CET4真题+解析+听力音频全3套",
        "2025年6月四级真题原卷（全3套）",
    ]
    for d in dirs:
        (lib_root / d).mkdir()

    return lib_root


# ---------------------------------------------------------------------------
# Tests: Default Library_Root
# ---------------------------------------------------------------------------


class TestDefaultLibraryRoot:
    """Tests for default Library_Root configuration."""

    def test_default_library_root_value(self, service: LibraryService) -> None:
        """Default Library_Root matches requirements.md specification."""
        assert service.library_root == DEFAULT_LIBRARY_ROOT
        assert service.library_root == r"C:\Users\86181\Desktop\cet4"

    def test_default_library_root_constant(self) -> None:
        """DEFAULT_LIBRARY_ROOT module constant is correct."""
        assert DEFAULT_LIBRARY_ROOT == r"C:\Users\86181\Desktop\cet4"


# ---------------------------------------------------------------------------
# Tests: Path validation — rejection cases (Req 1.3, 1.8)
# ---------------------------------------------------------------------------


class TestPathValidationRejection:
    """Tests for invalid path rejection."""

    def test_rejects_nonexistent_path(self, service: LibraryService) -> None:
        """Non-existent path → rejected with kind='not-found', reason='不存在'."""
        fake_path = r"C:\nonexistent\path\that\does\not\exist"
        result = service.set_library_root(fake_path)

        assert result is not None
        assert isinstance(result, LibraryRootUpdateError)
        assert result.path == fake_path
        assert result.kind == "not-found"
        assert result.reason == "不存在"

    def test_rejects_file_as_directory(
        self, service: LibraryService, tmp_path: Path
    ) -> None:
        """File path (not a directory) → rejected with kind='not-a-directory', reason='非目录'."""
        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("hello")

        result = service.set_library_root(str(file_path))

        assert result is not None
        assert isinstance(result, LibraryRootUpdateError)
        assert result.path == str(file_path)
        assert result.kind == "not-a-directory"
        assert result.reason == "非目录"

    @pytest.mark.skipif(
        sys.platform != "win32" or os.name != "nt",
        reason="Permission-based test only reliable on Windows with NTFS",
    )
    def test_rejects_unreadable_directory(
        self, service: LibraryService, tmp_path: Path
    ) -> None:
        """Unreadable directory → rejected with kind='not-readable', reason='不可读'.

        Note: This test is platform-specific and may be skipped on some systems.
        """
        unreadable = tmp_path / "unreadable"
        unreadable.mkdir()

        # Try to make it unreadable (platform-dependent)
        try:
            os.chmod(unreadable, 0o000)
            if os.access(unreadable, os.R_OK):
                pytest.skip("Cannot make directory unreadable on this platform")

            result = service.set_library_root(str(unreadable))

            assert result is not None
            assert isinstance(result, LibraryRootUpdateError)
            assert result.kind == "not-readable"
            assert result.reason == "不可读"
        finally:
            # Restore permissions for cleanup
            os.chmod(unreadable, 0o755)

    def test_preserves_original_config_on_rejection(
        self, service: LibraryService
    ) -> None:
        """On invalid path, original Library_Root is preserved unchanged."""
        original = service.library_root

        # Try to set an invalid path
        service.set_library_root(r"C:\nonexistent\path")

        # Original config preserved
        assert service.library_root == original

    def test_error_callback_invoked_on_rejection(
        self, service: LibraryService
    ) -> None:
        """on_error callback is invoked when path is rejected."""
        error_handler = MagicMock()
        service.on_error = error_handler

        service.set_library_root(r"C:\nonexistent\path")

        error_handler.assert_called_once()
        error = error_handler.call_args[0][0]
        assert isinstance(error, LibraryRootUpdateError)
        assert error.kind == "not-found"


# ---------------------------------------------------------------------------
# Tests: Path validation — acceptance cases (Req 1.2)
# ---------------------------------------------------------------------------


class TestPathValidationAcceptance:
    """Tests for valid path acceptance and scan triggering."""

    def test_accepts_valid_directory(
        self, service: LibraryService, valid_library_root: Path
    ) -> None:
        """Valid directory → accepted, Library_Root updated."""
        result = service.set_library_root(str(valid_library_root))

        assert result is None  # No error
        assert service.library_root == str(valid_library_root)

    def test_triggers_scan_on_valid_path(
        self, service: LibraryService, valid_library_root: Path
    ) -> None:
        """Valid path update triggers a scan and emits ScanResult."""
        scan_handler = MagicMock()
        service.on_scan_result = scan_handler

        service.set_library_root(str(valid_library_root))

        scan_handler.assert_called_once()
        result = scan_handler.call_args[0][0]
        assert isinstance(result, ScanResult)

    def test_scan_result_contains_paper_sets(
        self, service: LibraryService, populated_library_root: Path
    ) -> None:
        """Scan of populated directory produces 4 PaperSets."""
        scan_handler = MagicMock()
        service.on_scan_result = scan_handler

        service.set_library_root(str(populated_library_root))

        result = scan_handler.call_args[0][0]
        assert len(result.paper_sets) == 4

    def test_scan_result_has_12_papers(
        self, service: LibraryService, populated_library_root: Path
    ) -> None:
        """Scan produces 12 Paper records total (4 sets × 3 papers)."""
        scan_handler = MagicMock()
        service.on_scan_result = scan_handler

        service.set_library_root(str(populated_library_root))

        result = scan_handler.call_args[0][0]
        total_papers = sum(len(ps.papers) for ps in result.paper_sets)
        assert total_papers == 12


# ---------------------------------------------------------------------------
# Tests: scan() method
# ---------------------------------------------------------------------------


class TestScan:
    """Tests for LibraryService.scan() method."""

    def test_scan_with_invalid_default_path_returns_error(
        self, service: LibraryService
    ) -> None:
        """Scan with non-existent default path returns error."""
        # Default path likely doesn't exist in test environment
        result = service.scan()

        if isinstance(result, LibraryRootUpdateError):
            assert result.kind == "not-found"
        else:
            # If the default path happens to exist, it's a valid ScanResult
            assert isinstance(result, ScanResult)

    def test_scan_with_valid_path_returns_scan_result(
        self, valid_library_root: Path
    ) -> None:
        """Scan with valid path returns ScanResult."""
        service = LibraryService(_library_root=str(valid_library_root))
        result = service.scan()

        assert isinstance(result, ScanResult)

    def test_scan_emits_result_callback(
        self, valid_library_root: Path
    ) -> None:
        """Scan emits result via on_scan_result callback."""
        service = LibraryService(_library_root=str(valid_library_root))
        scan_handler = MagicMock()
        service.on_scan_result = scan_handler

        service.scan()

        scan_handler.assert_called_once()
        result = scan_handler.call_args[0][0]
        assert isinstance(result, ScanResult)

    def test_scan_emits_error_callback_on_invalid_path(self) -> None:
        """Scan emits error via on_error callback when path is invalid."""
        service = LibraryService(_library_root=r"C:\nonexistent\path")
        error_handler = MagicMock()
        service.on_error = error_handler

        result = service.scan()

        assert isinstance(result, LibraryRootUpdateError)
        error_handler.assert_called_once()

    def test_scan_duration_within_30_seconds(
        self, populated_library_root: Path
    ) -> None:
        """Scan completes within 30 seconds (Req 1.1)."""
        import time

        service = LibraryService(_library_root=str(populated_library_root))

        start = time.monotonic()
        result = service.scan()
        elapsed = time.monotonic() - start

        assert isinstance(result, ScanResult)
        assert elapsed < 30.0
        assert result.duration_ms < 30_000


# ---------------------------------------------------------------------------
# Tests: Callback behavior
# ---------------------------------------------------------------------------


class TestCallbacks:
    """Tests for callback registration and invocation."""

    def test_no_crash_without_callbacks(
        self, valid_library_root: Path
    ) -> None:
        """Service works fine without any callbacks registered."""
        service = LibraryService(_library_root=str(valid_library_root))
        # No callbacks set — should not crash
        result = service.scan()
        assert isinstance(result, ScanResult)

    def test_no_crash_without_error_callback(self) -> None:
        """Service works fine without error callback on failure."""
        service = LibraryService(_library_root=r"C:\nonexistent")
        # No error callback — should not crash
        result = service.scan()
        assert isinstance(result, LibraryRootUpdateError)

    def test_scan_result_callback_receives_correct_type(
        self, valid_library_root: Path
    ) -> None:
        """on_scan_result callback receives a ScanResult instance."""
        service = LibraryService(_library_root=str(valid_library_root))
        received = []
        service.on_scan_result = lambda r: received.append(r)

        service.scan()

        assert len(received) == 1
        assert isinstance(received[0], ScanResult)

    def test_error_callback_receives_correct_type(self) -> None:
        """on_error callback receives a LibraryRootUpdateError instance."""
        service = LibraryService(_library_root=r"C:\nonexistent")
        received = []
        service.on_error = lambda e: received.append(e)

        service.scan()

        assert len(received) == 1
        assert isinstance(received[0], LibraryRootUpdateError)


# ---------------------------------------------------------------------------
# Tests: Multiple updates
# ---------------------------------------------------------------------------


class TestMultipleUpdates:
    """Tests for sequential path updates."""

    def test_second_valid_update_replaces_first(
        self, tmp_path: Path
    ) -> None:
        """Second valid path update replaces the first."""
        dir1 = tmp_path / "dir1"
        dir1.mkdir()
        dir2 = tmp_path / "dir2"
        dir2.mkdir()

        service = LibraryService(_library_root=str(dir1))
        assert service.library_root == str(dir1)

        service.set_library_root(str(dir2))
        assert service.library_root == str(dir2)

    def test_failed_update_after_successful_preserves_last_good(
        self, tmp_path: Path
    ) -> None:
        """Failed update after a successful one preserves the last good path."""
        valid_dir = tmp_path / "valid"
        valid_dir.mkdir()

        service = LibraryService(_library_root=str(valid_dir))
        assert service.library_root == str(valid_dir)

        # Try invalid update
        service.set_library_root(r"C:\nonexistent")

        # Still has the valid path
        assert service.library_root == str(valid_dir)
