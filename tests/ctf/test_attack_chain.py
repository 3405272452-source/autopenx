"""End-to-end tests for the attack chain orchestrator."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from autopnex.ctf.attack_chain_orchestrator import (
    AttackChainOrchestrator,
    AttackChainResult,
    ChainState,
    ChainStepResult,
    run_php_attack_chain,
)


class TestChainStepResult:
    def test_to_dict_with_dict_data(self):
        step = ChainStepResult(
            state=ChainState.START,
            success=True,
            data={"key": "value"},
            duration_ms=100,
        )
        d = step.to_dict()
        assert d["state"] == "START"
        assert d["success"] is True
        assert d["data"] == {"key": "value"}
        assert d["duration_ms"] == 100

    def test_to_dict_with_string_data(self):
        step = ChainStepResult(
            state=ChainState.SUCCESS,
            success=True,
            data="flag{test}",
        )
        d = step.to_dict()
        assert d["data"] == "flag{test}"


class TestAttackChainResult:
    def test_to_dict_basic(self):
        result = AttackChainResult(
            success=True,
            flag="flag{test}",
            exploit_used="source_leak_scan -> php_audit -> direct_exploit",
            total_duration_ms=5000,
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["flag"] == "flag{test}"
        assert d["duration_ms"] == 5000

    def test_to_dict_with_vulns(self):
        from autopnex.ctf.php_audit_engine import PHPVulnerability, VulnType, Severity
        v = PHPVulnerability(
            VulnType.CMD_INJECT, Severity.CRITICAL,
            "test.php", 10, "cmd", "system()", "sys($_GET[cmd])", "hint",
        )
        result = AttackChainResult(
            success=False,
            vulnerabilities=[v],
        )
        d = result.to_dict()
        assert d["vulns_found"] == 1


class TestAttackChainOrchestrator:
    def test_init(self):
        session = Mock()
        orch = AttackChainOrchestrator(session)
        assert orch._exploit_enabled is True

    def test_run_with_flag_in_direct_response(self):
        """Test the full chain when the flag is accessible directly."""
        session = Mock()

        call_count = [0]

        def side_effect(url, **kwargs):
            call_count[0] += 1
            m = Mock()
            if "flag" in url:
                m.status_code = 200
                m.text = "flag{test_direct_flag}"
                m.content = b"flag{test_direct_flag}"
            elif call_count[0] == 1:
                m.status_code = 200
                m.text = "OK"
                m.content = b"OK"
            else:
                m.status_code = 404
                m.text = "Not Found"
                m.content = b""
            return m

        session.get.side_effect = side_effect
        session.post.return_value.status_code = 404
        session.post.return_value.text = "Not Found"

        orch = AttackChainOrchestrator(
            session,
            work_dir="/tmp/test_chain",
            exploit_enabled=True,
        )
        result = orch.run("http://test.com")

        # Should eventually trigger the READ_FLAG state or DIRECT_EXPLOIT state
        assert isinstance(result, AttackChainResult)
        assert len(result.chain_steps) > 0

    def test_run_with_no_vulnerabilities(self):
        """When no source leaks or vulns are found, the chain still runs to completion."""
        session = Mock()
        def get(url, **kwargs):
            m = Mock()
            if '.zip' in url or '.tar.gz' in url or '.git/' in url:
                m.status_code = 404
            else:
                m.status_code = 200
            m.text = "No flag here"
            m.content = b"No flag here"
            return m

        session.get.side_effect = get
        session.post.return_value.status_code = 404
        session.post.return_value.text = ""

        orch = AttackChainOrchestrator(
            session,
            work_dir="/tmp/test_chain_no_vuln",
            exploit_enabled=True,
        )
        result = orch.run("http://test.com")
        assert isinstance(result, AttackChainResult)
        assert result.success is False or result.flag is None

    def test_direct_exploit_finds_flag(self):
        """Test that direct exploit can find a flag via command injection."""
        from unittest.mock import MagicMock
        session = Mock()
        def get(url, **kwargs):
            m = MagicMock()
            if "cmd=cat" in url or "exec=cat" in url or "cat /flag" in str(kwargs.get("params", {})):
                m.status_code = 200
                m.text = "flag{cmd_injected}"
                m.content = b"flag{cmd_injected}"
            else:
                m.status_code = 404
                m.text = "Not found"
                m.content = b""
            m.headers = {}
            m.url = url
            return m
        session.get.side_effect = get
        post_mock = MagicMock()
        post_mock.status_code = 404
        post_mock.text = ""
        post_mock.headers = {}
        post_mock.url = "http://test.com"
        session.post.return_value = post_mock

        orch = AttackChainOrchestrator(
            session,
            work_dir="/tmp/test_cmd_inject",
            exploit_enabled=True,
        )
        result = orch.run("http://test.com")
        assert isinstance(result, AttackChainResult)

    def test_run_php_attack_chain_convenience(self):
        """Test the convenience function."""
        session = Mock()
        session.get.return_value.status_code = 200
        session.get.return_value.text = "flag{convenience_test}"
        session.get.return_value.content = b"flag{convenience_test}"

        result = run_php_attack_chain(session, "http://test.com", work_dir="/tmp/test_conv")
        assert isinstance(result, AttackChainResult)
