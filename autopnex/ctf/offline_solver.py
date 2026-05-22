"""无AI离线解题引擎 — 基于经验知识库的规则驱动自动化解题。

当 LLM 不可用时，使用决策树、模式匹配和 Payload 模板自动解题。
支持 Web、Pwn、Crypto、Misc、Reverse 五大题型。
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote

from .flag_engine import FlagEngine
from .models import (
    ChallengeInput,
    ChallengeProfile,
    ChallengeType,
    CTFResult,
)
from .knowledge_data import (
    load_patterns,
    get_patterns_for_challenge,
)

log = logging.getLogger("autopnex.ctf.offline_solver")


class OfflineSolver:
    """无AI离线解题引擎。

    基于经验知识库中的决策树和模式匹配，实现不依赖 LLM 的自动化解题。
    与 CTFModeController 接口兼容（接受 ChallengeInput，返回 CTFResult）。

    核心流程：
    1. 题目特征识别（启发式分类）
    2. 决策树驱动策略选择
    3. 自动化 Payload 测试
    4. Flag 提取与验证

    使用方式:
        solver = OfflineSolver(flag_format=r"flag\\{[^}]+\\}")
        result = await solver.solve(challenge_input)
    """

    def __init__(
        self,
        *,
        flag_format: str = r"[A-Za-z0-9_]+\{[^}]+\}",
        timeout: int = 300,
        max_payloads_per_vuln: int = 20,
    ) -> None:
        self.flag_format = flag_format
        self.timeout = timeout
        self.max_payloads_per_vuln = max_payloads_per_vuln
        self.flag_engine = FlagEngine()
        self._solve_log: List[Dict[str, Any]] = []
        self._start_time: Optional[float] = None

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    async def solve(self, challenge_input: ChallengeInput) -> CTFResult:
        """执行离线解题流程。

        Args:
            challenge_input: 题目输入信息。

        Returns:
            CTFResult 解题结果。
        """
        self._start_time = time.monotonic()
        self._solve_log = []
        steps_executed = 0

        log.info("离线解题引擎启动: target=%s", challenge_input.target)

        # 阶段 1: 题目特征识别
        profile = self._identify_challenge(challenge_input)
        self._log_step("identify", "题目识别", {
            "type": profile.challenge_type.value,
            "confidence": profile.confidence,
        })

        log.info(
            "题目识别完成: type=%s, confidence=%.2f",
            profile.challenge_type.value,
            profile.confidence,
        )

        # 阶段 2: 加载对应题型的解题模式
        patterns = get_patterns_for_challenge(
            profile.challenge_type.value,
            indicators=profile.potential_vulns + profile.key_hints,
        )

        if not patterns:
            # 加载所有该题型的模式
            all_data = load_patterns(profile.challenge_type.value)
            patterns = all_data.get("patterns", [])

        log.info("加载了 %d 个解题模式", len(patterns))

        # 阶段 3: 按匹配度逐一尝试策略
        for pattern in patterns:
            if self._is_timeout():
                break

            pattern_name = pattern.get("name", "unknown")
            methodology = pattern.get("methodology", [])
            payloads = pattern.get("payloads", [])

            log.info("尝试策略: %s", pattern_name)
            steps_executed += 1

            # 执行 Payload 测试
            if payloads:
                result = await self._test_payloads(
                    challenge_input, profile, pattern, payloads
                )
                if result:
                    elapsed_ms = self._get_elapsed_ms()
                    log.info(
                        "离线解题成功! flag=%s, strategy=%s, elapsed=%dms",
                        result, pattern_name, elapsed_ms,
                    )
                    return CTFResult(
                        success=True,
                        flag=result,
                        challenge_type=profile.challenge_type,
                        steps_executed=steps_executed,
                        total_duration_ms=elapsed_ms,
                        strategy_used=f"offline:{pattern_name}",
                        solve_log=self._solve_log,
                    )

            # 执行方法论步骤
            for step_desc in methodology:
                if self._is_timeout():
                    break
                steps_executed += 1
                step_result = await self._execute_methodology_step(
                    challenge_input, profile, step_desc, pattern
                )
                if step_result:
                    elapsed_ms = self._get_elapsed_ms()
                    return CTFResult(
                        success=True,
                        flag=step_result,
                        challenge_type=profile.challenge_type,
                        steps_executed=steps_executed,
                        total_duration_ms=elapsed_ms,
                        strategy_used=f"offline:{pattern_name}",
                        solve_log=self._solve_log,
                    )

        # 阶段 4: 通用 Flag 搜索（最后手段）
        flag = await self._generic_flag_search(challenge_input, profile)
        if flag:
            elapsed_ms = self._get_elapsed_ms()
            return CTFResult(
                success=True,
                flag=flag,
                challenge_type=profile.challenge_type,
                steps_executed=steps_executed + 1,
                total_duration_ms=elapsed_ms,
                strategy_used="offline:generic_search",
                solve_log=self._solve_log,
            )

        # 失败
        elapsed_ms = self._get_elapsed_ms()
        log.warning(
            "离线解题失败: target=%s, steps=%d, elapsed=%dms",
            challenge_input.target, steps_executed, elapsed_ms,
        )
        return CTFResult(
            success=False,
            error="offline_solver_exhausted",
            challenge_type=profile.challenge_type,
            steps_executed=steps_executed,
            total_duration_ms=elapsed_ms,
            solve_log=self._solve_log,
        )

    # ------------------------------------------------------------------
    # 阶段 1: 题目特征识别
    # ------------------------------------------------------------------

    def _identify_challenge(self, challenge_input: ChallengeInput) -> ChallengeProfile:
        """基于启发式规则识别题目类型和特征。"""
        target = challenge_input.target
        indicators: List[str] = []
        challenge_type = ChallengeType.UNKNOWN
        confidence = 0.3

        # 用户指定了题型
        if challenge_input.challenge_type:
            try:
                challenge_type = ChallengeType(challenge_input.challenge_type.lower())
                confidence = 0.9
            except ValueError:
                pass

        # URL 特征识别
        if challenge_type == ChallengeType.UNKNOWN:
            if target.startswith(("http://", "https://")):
                challenge_type = ChallengeType.WEB
                confidence = 0.8
                indicators.extend(["URL", "HTTP"])
            elif re.match(r"^[\w.-]+:\d+$", target):
                # host:port 格式
                port = int(target.split(":")[-1])
                if port in (80, 443, 8080, 8443, 3000, 5000, 8000):
                    challenge_type = ChallengeType.WEB
                    confidence = 0.7
                    indicators.append("web_port")
                else:
                    challenge_type = ChallengeType.PWN
                    confidence = 0.6
                    indicators.append("high_port")

        # 文件特征识别
        if challenge_type == ChallengeType.UNKNOWN and challenge_input.attachments:
            challenge_type, confidence, file_indicators = self._identify_from_files(
                challenge_input.attachments
            )
            indicators.extend(file_indicators)

        # 描述关键词识别
        if challenge_input.description:
            desc_type, desc_conf, desc_indicators = self._identify_from_description(
                challenge_input.description
            )
            if desc_conf > confidence:
                challenge_type = desc_type
                confidence = desc_conf
            indicators.extend(desc_indicators)

        return ChallengeProfile(
            challenge_type=challenge_type,
            confidence=min(confidence, 1.0),
            potential_vulns=indicators[:10],
            key_hints=list(challenge_input.hints),
        )

    def _identify_from_files(
        self, attachments: List[Path]
    ) -> Tuple[ChallengeType, float, List[str]]:
        """从附件文件类型推断题型。"""
        indicators: List[str] = []
        for path in attachments:
            suffix = path.suffix.lower()
            name = path.name.lower()

            if suffix in (".elf", ".bin", "") or name in ("pwn", "vuln", "challenge"):
                return ChallengeType.PWN, 0.7, ["binary", "elf"]
            elif suffix in (".exe", ".dll"):
                return ChallengeType.REVERSE, 0.7, ["pe", "windows"]
            elif suffix in (".py", ".sage") and self._file_has_crypto_keywords(path):
                return ChallengeType.CRYPTO, 0.8, ["python", "crypto"]
            elif suffix in (".py", ".sage"):
                indicators.append("python_script")
            elif suffix in (".pcap", ".pcapng"):
                return ChallengeType.MISC, 0.8, ["pcap", "traffic"]
            elif suffix in (".png", ".jpg", ".jpeg", ".bmp", ".gif"):
                return ChallengeType.MISC, 0.6, ["image", "stego"]
            elif suffix in (".zip", ".rar", ".7z", ".tar", ".gz"):
                return ChallengeType.MISC, 0.5, ["archive"]
            elif suffix in (".pdf",):
                return ChallengeType.MISC, 0.5, ["pdf"]

        return ChallengeType.UNKNOWN, 0.3, indicators

    def _identify_from_description(
        self, description: str
    ) -> Tuple[ChallengeType, float, List[str]]:
        """从题目描述关键词推断题型。"""
        desc_lower = description.lower()
        indicators: List[str] = []

        web_keywords = ["sql", "xss", "ssti", "lfi", "rce", "web", "http", "php", "flask", "django"]
        pwn_keywords = ["overflow", "buffer", "rop", "shellcode", "pwn", "exploit", "binary"]
        crypto_keywords = ["rsa", "aes", "cipher", "encrypt", "decrypt", "crypto", "key", "modulus"]
        misc_keywords = ["forensic", "stego", "hidden", "pcap", "memory", "dump"]
        rev_keywords = ["reverse", "crack", "keygen", "serial", "password", "check"]

        web_score = sum(1 for k in web_keywords if k in desc_lower)
        pwn_score = sum(1 for k in pwn_keywords if k in desc_lower)
        crypto_score = sum(1 for k in crypto_keywords if k in desc_lower)
        misc_score = sum(1 for k in misc_keywords if k in desc_lower)
        rev_score = sum(1 for k in rev_keywords if k in desc_lower)

        scores = {
            ChallengeType.WEB: web_score,
            ChallengeType.PWN: pwn_score,
            ChallengeType.CRYPTO: crypto_score,
            ChallengeType.MISC: misc_score,
            ChallengeType.REVERSE: rev_score,
        }

        best_type = max(scores, key=scores.get)  # type: ignore[arg-type]
        best_score = scores[best_type]

        if best_score == 0:
            return ChallengeType.UNKNOWN, 0.2, indicators

        confidence = min(0.3 + best_score * 0.15, 0.9)
        return best_type, confidence, indicators

    def _file_has_crypto_keywords(self, path: Path) -> bool:
        """检查文件是否包含密码学关键词。"""
        try:
            content = path.read_text(errors="ignore")[:5000]
            crypto_terms = ["rsa", "aes", "encrypt", "decrypt", "cipher", "modulus", "prime", "pow("]
            return any(term in content.lower() for term in crypto_terms)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 阶段 3: Payload 测试
    # ------------------------------------------------------------------

    async def _test_payloads(
        self,
        challenge_input: ChallengeInput,
        profile: ChallengeProfile,
        pattern: Dict[str, Any],
        payloads: Any,
    ) -> Optional[str]:
        """测试 Payload 列表，返回找到的 flag 或 None。"""
        target = challenge_input.target

        # 展平 payloads
        payload_list = self._flatten_payloads(payloads)
        payload_list = payload_list[: self.max_payloads_per_vuln]

        if not payload_list:
            return None

        pattern_id = pattern.get("id", "unknown")
        log.debug("测试 %d 个 Payload (pattern=%s)", len(payload_list), pattern_id)

        for i, payload in enumerate(payload_list):
            if self._is_timeout():
                break

            # 根据题型执行不同的测试方式
            if profile.challenge_type == ChallengeType.WEB:
                result = await self._test_web_payload(target, payload)
            else:
                # 非 Web 题型暂时跳过自动 Payload 测试
                continue

            if result:
                # 扫描 Flag
                candidates = self.flag_engine.scan(result)
                candidates += self.flag_engine.decode_and_scan(result)

                for candidate in candidates:
                    if self.flag_engine.validate(candidate.value, self.flag_format):
                        self._log_step("payload_test", f"Payload成功: {payload[:50]}", {
                            "payload": payload,
                            "flag": candidate.value,
                        })
                        return candidate.value

        return None

    async def _test_web_payload(self, target: str, payload: str) -> Optional[str]:
        """对 Web 目标测试单个 Payload。"""
        try:
            import httpx
        except ImportError:
            # 回退到 subprocess curl
            return await self._curl_test(target, payload)

        try:
            # 尝试在 URL 参数中注入
            parsed = urlparse(target)
            test_urls = []

            # 如果 URL 有查询参数，替换参数值
            if parsed.query:
                params = parsed.query.split("&")
                for i, param in enumerate(params):
                    if "=" in param:
                        key = param.split("=")[0]
                        new_params = params.copy()
                        new_params[i] = f"{key}={quote(payload)}"
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(new_params)}"
                        test_urls.append(test_url)
            else:
                # 尝试常见参数名
                for param_name in ["id", "page", "file", "name", "input", "cmd", "q"]:
                    test_url = f"{target}{'&' if '?' in target else '?'}{param_name}={quote(payload)}"
                    test_urls.append(test_url)

            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                for url in test_urls[:3]:  # 限制每个 payload 最多测试3个URL
                    try:
                        resp = await client.get(url)
                        return resp.text
                    except Exception:
                        continue

        except Exception as e:
            log.debug("Web Payload 测试异常: %s", e)

        return None

    async def _curl_test(self, target: str, payload: str) -> Optional[str]:
        """使用 curl 测试 Payload（回退方案）。"""
        try:
            url = f"{target}{'&' if '?' in target else '?'}id={quote(payload)}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-L", "--max-time", "5", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            return stdout.decode(errors="ignore")
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 方法论步骤执行
    # ------------------------------------------------------------------

    async def _execute_methodology_step(
        self,
        challenge_input: ChallengeInput,
        profile: ChallengeProfile,
        step_desc: str,
        pattern: Dict[str, Any],
    ) -> Optional[str]:
        """执行方法论中的单个步骤。"""
        target = challenge_input.target
        step_lower = step_desc.lower()

        # Web 题型的方法论步骤
        if profile.challenge_type == ChallengeType.WEB:
            return await self._execute_web_step(target, step_lower)

        return None

    async def _execute_web_step(self, target: str, step_desc: str) -> Optional[str]:
        """执行 Web 题型的方法论步骤。"""
        # 信息泄露检测
        if any(k in step_desc for k in ["信息", "泄露", "robots", "git", "备份"]):
            return await self._check_web_info_leak(target)

        # 目录扫描
        if any(k in step_desc for k in ["目录", "扫描", "路径"]):
            return await self._check_common_paths(target)

        return None

    # ------------------------------------------------------------------
    # Web 漏洞自动检测
    # ------------------------------------------------------------------

    async def _check_web_info_leak(self, target: str) -> Optional[str]:
        """检测 Web 信息泄露。"""
        leak_paths = [
            "/robots.txt", "/.git/HEAD", "/.git/config",
            "/.env", "/flag", "/flag.txt",
            "/.DS_Store", "/backup.sql", "/dump.sql",
            "/index.php.bak", "/index.php~", "/index.php.swp",
            "/.svn/entries", "/WEB-INF/web.xml",
            "/admin", "/console", "/debug",
        ]

        try:
            import httpx
            async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as client:
                for path in leak_paths:
                    if self._is_timeout():
                        break
                    try:
                        url = urljoin(target, path)
                        resp = await client.get(url)
                        if resp.status_code == 200 and len(resp.text) > 10:
                            # 扫描 Flag
                            flag = self._scan_for_flag(resp.text)
                            if flag:
                                self._log_step("info_leak", f"信息泄露: {path}", {
                                    "path": path,
                                    "flag": flag,
                                })
                                return flag
                    except Exception:
                        continue
        except ImportError:
            pass

        return None

    async def _check_common_paths(self, target: str) -> Optional[str]:
        """检查常见路径。"""
        paths = [
            "/flag", "/flag.txt", "/flag.php",
            "/api/flag", "/admin/flag", "/secret",
            "/source", "/src", "/backup",
        ]

        try:
            import httpx
            async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as client:
                for path in paths:
                    if self._is_timeout():
                        break
                    try:
                        url = urljoin(target, path)
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            flag = self._scan_for_flag(resp.text)
                            if flag:
                                return flag
                    except Exception:
                        continue
        except ImportError:
            pass

        return None

    # ------------------------------------------------------------------
    # 通用 Flag 搜索
    # ------------------------------------------------------------------

    async def _generic_flag_search(
        self, challenge_input: ChallengeInput, profile: ChallengeProfile
    ) -> Optional[str]:
        """通用 Flag 搜索 — 最后手段。"""
        target = challenge_input.target

        if profile.challenge_type == ChallengeType.WEB:
            # 尝试直接访问目标页面
            try:
                import httpx
                async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                    resp = await client.get(target)
                    flag = self._scan_for_flag(resp.text)
                    if flag:
                        return flag

                    # 查看页面源码中的注释
                    flag = self._scan_for_flag(resp.text)
                    if flag:
                        return flag
            except Exception:
                pass

        # 检查附件文件中的 Flag
        for attachment in challenge_input.attachments:
            try:
                content = attachment.read_text(errors="ignore")
                flag = self._scan_for_flag(content)
                if flag:
                    self._log_step("file_scan", f"文件中发现Flag: {attachment.name}", {
                        "file": str(attachment),
                    })
                    return flag
            except Exception:
                try:
                    content = attachment.read_bytes()
                    candidates = self.flag_engine.scan_binary(content)
                    for c in candidates:
                        if self.flag_engine.validate(c.value, self.flag_format):
                            return c.value
                except Exception:
                    pass

        return None

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _scan_for_flag(self, content: str) -> Optional[str]:
        """扫描内容中的 Flag。"""
        if not content:
            return None

        candidates = self.flag_engine.scan(content)
        candidates += self.flag_engine.decode_and_scan(content)

        for candidate in candidates:
            if self.flag_engine.validate(candidate.value, self.flag_format):
                return candidate.value

        return None

    def _flatten_payloads(self, payloads: Any) -> List[str]:
        """展平 Payload 数据结构为字符串列表。"""
        if isinstance(payloads, list):
            result = []
            for item in payloads:
                if isinstance(item, str):
                    result.append(item)
                elif isinstance(item, list):
                    result.extend(str(x) for x in item)
            return result
        elif isinstance(payloads, dict):
            result = []
            for key, val in payloads.items():
                if isinstance(val, list):
                    result.extend(str(x) for x in val)
                elif isinstance(val, str):
                    result.append(val)
            return result
        elif isinstance(payloads, str):
            return [payloads]
        return []

    def _is_timeout(self) -> bool:
        """检查是否超时。"""
        if self._start_time is None:
            return False
        return (time.monotonic() - self._start_time) >= self.timeout

    def _get_elapsed_ms(self) -> int:
        """获取已用时间（毫秒）。"""
        if self._start_time is None:
            return 0
        return int((time.monotonic() - self._start_time) * 1000)

    def _log_step(self, tool: str, description: str, details: Dict[str, Any]) -> None:
        """记录解题步骤。"""
        self._solve_log.append({
            "tool": tool,
            "description": description,
            "details": details,
            "elapsed_ms": self._get_elapsed_ms(),
        })
