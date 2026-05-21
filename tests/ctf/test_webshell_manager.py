"""Tests for webshell manager module."""
import pytest
from unittest.mock import Mock, patch
from autopnex.ctf.webshell_manager import (
    WebshellManager,
    WebshellResult,
    WEBSHELLS,
    FLAG_PATHS,
    FLAG_READ_COMMANDS,
)


class TestWebshellTemplates:
    def test_all_have_three_parts(self):
        for name, value in WEBSHELLS.items():
            assert len(value) == 3
            fname, content, hint = value
            assert fname.endswith((".php", ".gif"))
            assert isinstance(content, bytes)
            assert len(content) > 5
            assert isinstance(hint, str)


class TestWebshellManager:
    def test_initialization(self):
        session = Mock()
        mgr = WebshellManager(session)
        assert len(mgr.active_shells) == 0

    def test_deploy_via_upload_success(self):
        session = Mock()
        session.post.return_value.status_code = 200
        session.post.return_value.text = "uploaded"
        mgr = WebshellManager(session)
        results = mgr.deploy_via_upload(
            "http://test.com/upload.php",
            shell_types=["classic", "get_cmd"],
        )
        assert len(results) == 2
        assert all(r.deployed for r in results)

    def test_deploy_via_upload_error(self):
        import requests
        session = Mock()
        session.post.side_effect = requests.ConnectionError("fail")
        mgr = WebshellManager(session)
        results = mgr.deploy_via_upload(
            "http://test.com/upload.php",
            shell_types=["classic"],
        )
        assert not results[0].deployed

    def test_verify_get_shell(self):
        session = Mock()
        session.get.return_value.text = "AUTOPENX_OK_7a3f something else"
        session.get.return_value.status_code = 200
        mgr = WebshellManager(session)
        assert mgr.verify("http://test.com/shell.php?cmd=echo%20AUTOPENX_OK_7a3f", "get_cmd") is True

    def test_verify_post_shell(self):
        session = Mock()
        session.post.return_value.text = "AUTOPENX_OK_7a3f"
        session.post.return_value.status_code = 200
        mgr = WebshellManager(session)
        assert mgr.verify("http://test.com/shell.php", "classic") is True

    def test_verify_failure(self):
        session = Mock()
        session.post.return_value.text = "error: function disabled"
        session.get.return_value.text = "404"
        mgr = WebshellManager(session)
        assert mgr.verify("http://test.com/shell.php", "classic") is False

    def test_execute_command(self):
        session = Mock()
        session.post.return_value.text = "uid=33(www-data) gid=33(www-data)"
        session.post.return_value.status_code = 200
        mgr = WebshellManager(session)
        result = mgr.execute("http://test.com/shell.php", "id", "classic")
        assert "uid=" in result["output"]

    def test_read_flag_found(self):
        session = Mock()
        # First call: find
        session.post.return_value.text = "flag{test_flag_123}\n"
        session.post.return_value.status_code = 200
        session.get.return_value.text = "flag{test_flag_123}\n"
        session.get.return_value.status_code = 200
        mgr = WebshellManager(session)
        result = mgr.read_flag("http://test.com/shell.php", "classic")
        # Should find flag{test_flag_123}
        assert result is not None

    def test_webshell_result_to_dict(self):
        r = WebshellResult(
            url="http://test.com/shell.php",
            shell_type="classic",
            deployed=True,
            verified=True,
            deploy_method="upload",
            response_body="upload success",
        )
        d = r.to_dict()
        assert d["url"] == "http://test.com/shell.php"
        assert d["deployed"] is True
        assert d["verified"] is True


class TestFlagCommands:
    def test_flag_paths_non_empty(self):
        assert len(FLAG_PATHS) > 5

    def test_flag_commands_non_empty(self):
        assert len(FLAG_READ_COMMANDS) > 5

    def test_flag_commands_include_cat(self):
        cat_commands = [c for c in FLAG_READ_COMMANDS if "cat" in c or "tac" in c or "head" in c]
        assert len(cat_commands) > 0
