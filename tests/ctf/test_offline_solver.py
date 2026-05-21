"""无AI离线解题引擎单元测试。"""
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from autopnex.ctf.offline_solver import OfflineSolver
from autopnex.ctf.models import ChallengeInput, ChallengeType


class TestOfflineSolverIdentification:
    """测试题目特征识别。"""

    def _make_solver(self):
        return OfflineSolver(flag_format=r"flag\{[^}]+\}", timeout=30)

    def test_identify_web_from_url(self):
        """HTTP URL 应识别为 Web 题。"""
        solver = self._make_solver()
        inp = ChallengeInput(target="http://challenge.ctf.com:8080")
        profile = solver._identify_challenge(inp)
        assert profile.challenge_type == ChallengeType.WEB
        assert profile.confidence >= 0.7

    def test_identify_web_from_https(self):
        """HTTPS URL 应识别为 Web 题。"""
        solver = self._make_solver()
        inp = ChallengeInput(target="https://web.ctf.com/login")
        profile = solver._identify_challenge(inp)
        assert profile.challenge_type == ChallengeType.WEB

    def test_identify_pwn_from_high_port(self):
        """高端口号应识别为 Pwn 题。"""
        solver = self._make_solver()
        inp = ChallengeInput(target="challenge.ctf.com:31337")
        profile = solver._identify_challenge(inp)
        assert profile.challenge_type == ChallengeType.PWN

    def test_identify_web_from_web_port(self):
        """Web 端口应识别为 Web 题。"""
        solver = self._make_solver()
        inp = ChallengeInput(target="challenge.ctf.com:8080")
        profile = solver._identify_challenge(inp)
        assert profile.challenge_type == ChallengeType.WEB

    def test_identify_from_user_specified_type(self):
        """用户指定题型应优先使用。"""
        solver = self._make_solver()
        inp = ChallengeInput(
            target="http://example.com",
            challenge_type="crypto",
        )
        profile = solver._identify_challenge(inp)
        assert profile.challenge_type == ChallengeType.CRYPTO
        assert profile.confidence >= 0.9

    def test_identify_from_description_keywords(self):
        """描述中的关键词应辅助识别。"""
        solver = self._make_solver()
        inp = ChallengeInput(
            target="nc challenge.com 9999",
            description="RSA encryption with small e, find the plaintext",
        )
        profile = solver._identify_challenge(inp)
        assert profile.challenge_type == ChallengeType.CRYPTO


class TestOfflineSolverPayloads:
    """测试 Payload 展平和处理。"""

    def _make_solver(self):
        return OfflineSolver(flag_format=r"flag\{[^}]+\}", timeout=30)

    def test_flatten_list_payloads(self):
        """列表 Payload 应正确展平。"""
        solver = self._make_solver()
        payloads = ["payload1", "payload2", "payload3"]
        result = solver._flatten_payloads(payloads)
        assert result == ["payload1", "payload2", "payload3"]

    def test_flatten_dict_payloads(self):
        """字典 Payload 应正确展平。"""
        solver = self._make_solver()
        payloads = {
            "detection": ["{{7*7}}", "${7*7}"],
            "rce": ["os.popen('cat /flag')"],
        }
        result = solver._flatten_payloads(payloads)
        assert len(result) == 3
        assert "{{7*7}}" in result

    def test_flatten_nested_list(self):
        """嵌套列表应展平。"""
        solver = self._make_solver()
        payloads = [["a", "b"], "c"]
        result = solver._flatten_payloads(payloads)
        assert "a" in result
        assert "b" in result
        assert "c" in result

    def test_flatten_empty(self):
        """空输入应返回空列表。"""
        solver = self._make_solver()
        assert solver._flatten_payloads(None) == []
        assert solver._flatten_payloads([]) == []
        assert solver._flatten_payloads({}) == []


class TestOfflineSolverFlagScan:
    """测试 Flag 扫描功能。"""

    def _make_solver(self):
        return OfflineSolver(flag_format=r"flag\{[^}]+\}", timeout=30)

    def test_scan_finds_flag_in_text(self):
        """应能从文本中找到 Flag。"""
        solver = self._make_solver()
        content = "Congratulations! The flag is flag{offline_solver_works_2024}"
        result = solver._scan_for_flag(content)
        assert result == "flag{offline_solver_works_2024}"

    def test_scan_returns_none_for_no_flag(self):
        """无 Flag 时应返回 None。"""
        solver = self._make_solver()
        result = solver._scan_for_flag("Hello World, no flag here")
        assert result is None

    def test_scan_empty_content(self):
        """空内容应返回 None。"""
        solver = self._make_solver()
        assert solver._scan_for_flag("") is None
        assert solver._scan_for_flag(None) is None


class TestOfflineSolverSolve:
    """测试完整解题流程。"""

    @pytest.mark.asyncio
    async def test_solve_returns_ctf_result(self):
        """solve 应返回 CTFResult 对象。"""
        solver = OfflineSolver(flag_format=r"flag\{[^}]+\}", timeout=5)
        inp = ChallengeInput(target="http://example.com")
        result = await solver.solve(inp)
        # 不一定成功（没有真实目标），但应返回有效结果
        assert result is not None
        assert result.success is False or result.success is True
        assert result.total_duration_ms >= 0

    @pytest.mark.asyncio
    async def test_solve_timeout(self):
        """超时应正确处理。"""
        solver = OfflineSolver(flag_format=r"flag\{[^}]+\}", timeout=0)
        inp = ChallengeInput(target="http://example.com")
        result = await solver.solve(inp)
        # 超时为0，应快速返回
        assert result is not None

    @pytest.mark.asyncio
    async def test_solve_with_flag_in_attachment(self, tmp_path):
        """附件中包含 Flag 时应能找到。"""
        # 创建包含 flag 的临时文件
        flag_file = tmp_path / "source.py"
        flag_file.write_text("# flag{found_in_source_code_123}")

        solver = OfflineSolver(flag_format=r"flag\{[^}]+\}", timeout=10)
        inp = ChallengeInput(
            target="http://example.com",
            attachments=[flag_file],
        )
        result = await solver.solve(inp)
        assert result.success is True
        assert result.flag == "flag{found_in_source_code_123}"



