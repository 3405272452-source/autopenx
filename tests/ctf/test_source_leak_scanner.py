"""Tests for source leak scanner module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from autopnex.ctf.source_leak_scanner import (
    SourceLeakScanner,
    LeakResult,
    _parse_git_index,
    parse_git_blob,
    BACKUP_PATHS,
    GIT_LEAK_PATHS,
)


class TestSourceLeakScanner:
    """Test source leak detection functionality."""

    def test_probe_backup_files_found(self):
        session = Mock()
        session.get.return_value.status_code = 200
        session.get.return_value.content = b"PK\x03\x04" + b"\x00" * 2000  # ZIP magic
        scanner = SourceLeakScanner(session, work_dir="/tmp/test_leaks")
        results = scanner.probe_backup_files("http://test.com")
        assert len(results) > 0

    def test_probe_backup_files_not_found(self):
        session = Mock()
        session.get.return_value.status_code = 404
        scanner = SourceLeakScanner(session, work_dir="/tmp/test_leaks")
        results = scanner.probe_backup_files("http://test.com")
        assert len(results) == 0

    def test_probe_git_leak_no_leak(self):
        session = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.content = b""
        session.get.return_value = mock_resp
        scanner = SourceLeakScanner(session, work_dir="/tmp/test_leaks")
        results = scanner.probe_git_leak("http://test.com")
        assert len(results) == 0

    def test_detect_framework_laravel(self):
        session = Mock()
        def mock_get(url, timeout=None, allow_redirects=True):
            m = Mock()
            if "composer.json" in url:
                m.status_code = 200
                m.content = b'{"require": {"laravel/framework": "8.0"}}'
                m.text = '{"require": {"laravel/framework": "8.0"}}'
            else:
                m.status_code = 404
                m.content = b""
                m.text = ""
            return m
        session.get = mock_get
        scanner = SourceLeakScanner(session, work_dir="/tmp/test_leaks")
        fw = scanner.detect_framework("http://test.com")
        assert fw == "Laravel"

    def test_empty_result_on_no_leak(self):
        session = Mock()
        session.get.return_value.status_code = 404
        session.get.return_value.content = b""
        scanner = SourceLeakScanner(session, work_dir="/tmp/test_leaks")
        results = scanner.scan_all("http://test.com")
        assert len(results) >= 1


class TestParseGitIndex:
    def test_empty_data(self):
        assert _parse_git_index(b"") == []

    def test_short_data(self):
        assert _parse_git_index(b"DIRC") == []

    def test_valid_index(self):
        import struct
        header = b"DIRC"
        header += struct.pack(">I", 2)   # version 2
        header += struct.pack(">I", 1)   # 1 entry
        # Entry: ctime, mtime, dev, ino, mode, uid, gid, size, sha1, flags, path
        entry = b"\x00" * 62            # 40 + 16 + 4 + 2 = 62 bytes
        entry += b"test.php\x00"
        # Pad to 8
        entry += b"\x00" * (8 - len(entry) % 8)
        data = header + entry
        results = _parse_git_index(data)
        assert len(results) == 1
        # SHA is all zeros
        assert results[0][0] == "0000000000000000000000000000000000000000"
        assert results[0][1] == "test.php"


class TestLeakResult:
    def test_to_dict(self):
        leak = LeakResult(
            leak_type="backup_leak",
            url="http://test.com/www.zip",
            local_path="/tmp/www.zip",
            files=["index.php", "config.php"],
            framework="Laravel",
        )
        d = leak.to_dict()
        assert d["leak_type"] == "backup_leak"
        assert d["url"] == "http://test.com/www.zip"
        assert d["file_count"] == 2
        assert d["framework"] == "Laravel"

    def test_empty_framework(self):
        leak = LeakResult(leak_type="none", url="http://test.com")
        d = leak.to_dict()
        assert d["framework"] == ""
        assert d["file_count"] == 0
