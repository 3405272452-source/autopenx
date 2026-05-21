"""CTF 题目分析器 — 利用 LLM 和启发式规则分析 CTF 题目。

结合文件类型启发式、URL 特征启发式、LLM 语义分析和知识库匹配，
通过投票算法综合判断题目类型并提取关键信息。
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .models import ChallengeInput, ChallengeProfile, ChallengeType

if TYPE_CHECKING:
    from autopnex.orchestrator.llm_client import LLMClient


# ---------------------------------------------------------------------------
# 提示词模板
# ---------------------------------------------------------------------------

CTF_CLASSIFICATION_PROMPT = """\
你是一个 CTF（Capture The Flag）竞赛专家。请根据以下题目信息判断题目类型。

题目类型只能是以下之一：
- web: Web 安全题（SQL注入、XSS、SSTI、文件包含、反序列化等）
- pwn: 二进制漏洞利用题（栈溢出、堆利用、格式化字符串等）
- crypto: 密码学题（RSA、AES、古典密码、哈希等）
- misc: 杂项题（隐写、取证、流量分析、编码等）
- reverse: 逆向工程题（反编译、算法分析、混淆等）
- unknown: 无法判断

请严格按照以下 JSON 格式回复，不要包含其他内容：
{
  "type": "<题目类型>",
  "confidence": <0.0-1.0的置信度>,
  "tech_stack": ["<技术栈1>", "<技术栈2>"],
  "potential_vulns": ["<潜在漏洞1>", "<潜在漏洞2>"],
  "reasoning": "<分类理由>"
}
"""

CTF_HINTS_EXTRACTION_PROMPT = """\
你是一个 CTF 竞赛专家。请从以下题目描述中提取关键线索和提示信息。

提取规则：
1. 技术关键词（如框架名、协议名、算法名）
2. 版本号信息
3. 明显的提示词或暗示
4. 可能的漏洞类型线索
5. 文件名或路径信息

请以 JSON 数组格式返回提取到的线索列表，每个线索是一个字符串：
["线索1", "线索2", "线索3"]
"""


# ---------------------------------------------------------------------------
# 密码学关键词（用于文件启发式分类）
# ---------------------------------------------------------------------------

CRYPTO_KEYWORDS = frozenset([
    "rsa", "aes", "des", "encrypt", "decrypt", "cipher",
    "prime", "modulus", "exponent", "signature", "hmac",
    "xor", "phi", "gcd",
    "from Crypto", "from Cryptodome", "import gmpy2",
    "from sage", "from sympy", "inverse_mod", "long_to_bytes",
    "bytes_to_long", "getPrime", "isPrime",
])


# ---------------------------------------------------------------------------
# ChallengeAnalyzer
# ---------------------------------------------------------------------------


class ChallengeAnalyzer:
    """分析 CTF 题目，提取结构化信息。

    结合 LLM 语义分析、文件类型启发式、URL 特征启发式和知识库匹配，
    通过投票算法综合判断题目类型并生成 ChallengeProfile。
    """

    def __init__(
        self,
        llm_client: "LLMClient",
        knowledge_base: Optional[Any] = None,
    ) -> None:
        """初始化题目分析器。

        Args:
            llm_client: LLM 客户端实例，用于语义分析。
            knowledge_base: CTF 知识库实例（可选），用于相似题目匹配。
        """
        self.llm_client = llm_client
        self.knowledge_base = knowledge_base

    # ------------------------------------------------------------------
    # 文件类型启发式分类
    # ------------------------------------------------------------------

    def detect_from_file(self, file_path: Path) -> ChallengeType:
        """根据附件文件类型推断题型。

        分类规则：
        - ELF/PE 二进制文件 → PWN 或 REVERSE（有调试符号则为 REVERSE）
        - .py/.sage 含密码学关键词 → CRYPTO
        - .pcap/.png/.jpg/.pdf/.zip → MISC
        - .php/.html/.js → WEB
        - 其他 → UNKNOWN

        Args:
            file_path: 附件文件路径。

        Returns:
            推断的题目类型。
        """
        file_path = Path(file_path)
        suffix = file_path.suffix.lower()

        # 检查二进制文件（ELF/PE）
        if self._is_binary_executable(file_path):
            if self._has_debug_symbols(file_path):
                return ChallengeType.REVERSE
            return ChallengeType.PWN

        # Python/Sage 文件含密码学关键词 → CRYPTO
        if suffix in (".py", ".sage"):
            if self._contains_crypto_keywords(file_path):
                return ChallengeType.CRYPTO
            return ChallengeType.UNKNOWN

        # 常见 Misc 文件类型
        if suffix in (".pcap", ".pcapng", ".png", ".jpg", ".jpeg",
                      ".gif", ".bmp", ".pdf", ".zip", ".tar", ".gz",
                      ".7z", ".rar"):
            return ChallengeType.MISC

        # Web 相关文件
        if suffix in (".php", ".html", ".htm", ".js", ".css", ".jsp",
                      ".asp", ".aspx"):
            return ChallengeType.WEB

        return ChallengeType.UNKNOWN

    # ------------------------------------------------------------------
    # URL 特征启发式分类
    # ------------------------------------------------------------------

    def _classify_from_url(self, url: str) -> ChallengeType:
        """根据 URL 特征推断题型。

        分类规则：
        - http/https 开头 → WEB
        - 高端口号（1024-65535）且无 http → PWN
        - 其他 → UNKNOWN

        Args:
            url: 目标 URL 或地址。

        Returns:
            推断的题目类型。
        """
        if not url:
            return ChallengeType.UNKNOWN

        # http/https URL → WEB
        if url.startswith(("http://", "https://")):
            return ChallengeType.WEB

        # 检查高端口号（host:port 格式，无 http 前缀）→ PWN
        # 匹配 "host:port" 或 "nc host port" 格式
        port = self._extract_port(url)
        if port is not None and 1024 <= port <= 65535:
            return ChallengeType.PWN

        return ChallengeType.UNKNOWN

    # ------------------------------------------------------------------
    # LLM 语义分类
    # ------------------------------------------------------------------

    async def classify_type(
        self,
        description: str,
        url: Optional[str] = None,
    ) -> ChallengeType:
        """通过 LLM 语义分析对题目进行分类。

        构建提示词请求 LLM 分析题目描述，解析返回的 JSON 提取分类结果。

        Args:
            description: 题目描述文本。
            url: 目标 URL（可选），提供额外上下文。

        Returns:
            LLM 判断的题目类型。
        """
        user_content = f"题目描述：{description}"
        if url:
            user_content += f"\n目标地址：{url}"

        messages = [
            {"role": "system", "content": CTF_CLASSIFICATION_PROMPT},
            {"role": "user", "content": user_content},
        ]

        try:
            response = self.llm_client.chat(messages, temperature=0.1)
            content = response.get("content", "")
            return self._parse_classification_response(content)
        except Exception:
            return ChallengeType.UNKNOWN

    # ------------------------------------------------------------------
    # 关键线索提取
    # ------------------------------------------------------------------

    async def extract_hints(self, description: str) -> List[str]:
        """从题目描述中提取关键提示信息。

        使用 LLM 分析题目描述，提取技术关键词、版本号、
        提示词等关键线索。

        Args:
            description: 题目描述文本。

        Returns:
            提取到的关键线索列表。
        """
        if not description or not description.strip():
            return []

        messages = [
            {"role": "system", "content": CTF_HINTS_EXTRACTION_PROMPT},
            {"role": "user", "content": description},
        ]

        try:
            response = self.llm_client.chat(messages, temperature=0.1)
            content = response.get("content", "")
            return self._parse_hints_response(content)
        except Exception:
            return []

    # ------------------------------------------------------------------
    # 综合分析（投票算法）
    # ------------------------------------------------------------------

    async def analyze(self, challenge_input: ChallengeInput) -> ChallengeProfile:
        """分析题目输入，返回结构化的题目画像。

        综合多种分类策略进行投票：
        1. 文件类型启发式（权重 0.8）
        2. URL 特征启发式（权重 0.5）
        3. LLM 语义分类（权重 1.0）
        4. 知识库匹配（权重 0.3）

        Args:
            challenge_input: 用户提交的题目信息。

        Returns:
            结构化的题目画像。
        """
        votes: Dict[ChallengeType, float] = defaultdict(float)
        tech_stack: List[str] = []
        potential_vulns: List[str] = []
        key_hints: List[str] = []
        raw_analysis = ""

        # 策略 1: 文件类型启发式
        for attachment in challenge_input.attachments:
            file_type = self.detect_from_file(attachment)
            if file_type != ChallengeType.UNKNOWN:
                votes[file_type] += 0.8

        # 策略 2: URL 特征启发式
        url_type = self._classify_from_url(challenge_input.target)
        if url_type != ChallengeType.UNKNOWN:
            votes[url_type] += 0.5

        # 策略 3: LLM 语义分析
        if challenge_input.description:
            llm_result = await self._llm_classify_full(
                challenge_input.description,
                challenge_input.target,
            )
            if llm_result:
                llm_type = llm_result.get("type", ChallengeType.UNKNOWN)
                llm_confidence = llm_result.get("confidence", 0.5)
                if llm_type != ChallengeType.UNKNOWN:
                    votes[llm_type] += llm_confidence
                tech_stack = llm_result.get("tech_stack", [])
                potential_vulns = llm_result.get("potential_vulns", [])
                raw_analysis = llm_result.get("reasoning", "")

            # 提取关键线索
            key_hints = await self.extract_hints(challenge_input.description)

        # 策略 4: 知识库匹配
        if self.knowledge_base and challenge_input.description:
            try:
                similar = self.knowledge_base.query_similar_by_description(
                    challenge_input.description
                )
                for record in similar[:3]:
                    votes[record.challenge_type] += 0.3 * getattr(
                        record, "similarity_score", 0.5
                    )
            except (AttributeError, Exception):
                pass

        # 用户指定的题型优先级最高
        if challenge_input.challenge_type:
            try:
                user_type = ChallengeType(challenge_input.challenge_type.lower())
                votes[user_type] += 2.0
            except ValueError:
                pass

        # 综合投票
        if votes:
            best_type = max(votes, key=lambda k: votes[k])
            total_score = sum(votes.values())
            confidence = votes[best_type] / total_score if total_score > 0 else 0.0
            confidence = min(confidence, 1.0)
        else:
            best_type = ChallengeType.UNKNOWN
            confidence = 0.0

        # 添加来自 hints 的线索
        key_hints.extend(challenge_input.hints)

        return ChallengeProfile(
            challenge_type=best_type,
            tech_stack=list(dict.fromkeys(tech_stack)),  # 去重保序
            potential_vulns=list(dict.fromkeys(potential_vulns)),
            key_hints=list(dict.fromkeys(key_hints)),
            confidence=confidence,
            raw_analysis=raw_analysis,
        )

    # ------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------

    def _is_binary_executable(self, file_path: Path) -> bool:
        """检查文件是否为 ELF 或 PE 二进制可执行文件。"""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
            # ELF magic: 0x7f 'E' 'L' 'F'
            if magic[:4] == b"\x7fELF":
                return True
            # PE magic: 'M' 'Z'
            if magic[:2] == b"MZ":
                return True
            return False
        except (OSError, IOError):
            return False

    def _has_debug_symbols(self, file_path: Path) -> bool:
        """检查二进制文件是否包含调试符号。

        通过搜索 .debug_ 或 .symtab 段名来判断。
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            # 检查常见的调试段名
            debug_markers = [
                b".debug_info",
                b".debug_line",
                b".debug_str",
                b".symtab",
                b".strtab",
                b"DWARF",
            ]
            return any(marker in content for marker in debug_markers)
        except (OSError, IOError):
            return False

    def _contains_crypto_keywords(self, file_path: Path) -> bool:
        """检查文件内容是否包含密码学相关关键词。"""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            content_lower = content.lower()
            # 检查是否包含足够多的密码学关键词
            matches = sum(
                1 for kw in CRYPTO_KEYWORDS if kw.lower() in content_lower
            )
            return matches >= 2
        except (OSError, IOError):
            return False

    def _extract_port(self, url: str) -> Optional[int]:
        """从地址字符串中提取端口号。

        支持格式：
        - host:port
        - nc host port
        - host port
        """
        # 匹配 "nc host port" 格式
        nc_match = re.match(r"nc\s+\S+\s+(\d+)", url)
        if nc_match:
            try:
                return int(nc_match.group(1))
            except ValueError:
                pass

        # 匹配 "host:port" 格式
        colon_match = re.search(r":(\d+)(?:/|$|\s)", url + " ")
        if colon_match:
            try:
                return int(colon_match.group(1))
            except ValueError:
                pass

        # 匹配 "host port" 格式（空格分隔）
        parts = url.strip().split()
        if len(parts) >= 2 and parts[-1].isdigit():
            try:
                return int(parts[-1])
            except ValueError:
                pass

        return None

    async def _llm_classify_full(
        self,
        description: str,
        url: str,
    ) -> Optional[Dict[str, Any]]:
        """调用 LLM 进行完整的题目分类分析。

        Returns:
            包含 type, confidence, tech_stack, potential_vulns, reasoning 的字典，
            或在失败时返回 None。
        """
        user_content = f"题目描述：{description}"
        if url:
            user_content += f"\n目标地址：{url}"

        messages = [
            {"role": "system", "content": CTF_CLASSIFICATION_PROMPT},
            {"role": "user", "content": user_content},
        ]

        try:
            response = self.llm_client.chat(messages, temperature=0.1)
            content = response.get("content", "")
            return self._parse_full_classification(content)
        except Exception:
            return None

    def _parse_classification_response(self, content: str) -> ChallengeType:
        """解析 LLM 分类响应，提取题目类型。"""
        parsed = self._parse_full_classification(content)
        if parsed:
            return parsed.get("type", ChallengeType.UNKNOWN)
        return ChallengeType.UNKNOWN

    def _parse_full_classification(
        self, content: str
    ) -> Optional[Dict[str, Any]]:
        """解析 LLM 完整分类响应。"""
        import json

        # 尝试从响应中提取 JSON
        try:
            # 尝试直接解析
            data = json.loads(content)
        except json.JSONDecodeError:
            # 尝试从 markdown 代码块中提取
            json_match = re.search(
                r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
            )
            if json_match:
                try:
                    data = json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    return None
            else:
                # 尝试找到 JSON 对象
                brace_match = re.search(r"\{[^{}]*\}", content, re.DOTALL)
                if brace_match:
                    try:
                        data = json.loads(brace_match.group(0))
                    except json.JSONDecodeError:
                        return None
                else:
                    return None

        # 解析类型
        type_str = data.get("type", "unknown").lower()
        try:
            challenge_type = ChallengeType(type_str)
        except ValueError:
            challenge_type = ChallengeType.UNKNOWN

        return {
            "type": challenge_type,
            "confidence": float(data.get("confidence", 0.5)),
            "tech_stack": data.get("tech_stack", []),
            "potential_vulns": data.get("potential_vulns", []),
            "reasoning": data.get("reasoning", ""),
        }

    def _parse_hints_response(self, content: str) -> List[str]:
        """解析 LLM 线索提取响应。"""
        import json

        try:
            hints = json.loads(content)
            if isinstance(hints, list):
                return [str(h) for h in hints if h]
        except json.JSONDecodeError:
            # 尝试从 markdown 代码块中提取
            json_match = re.search(
                r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
            )
            if json_match:
                try:
                    hints = json.loads(json_match.group(1))
                    if isinstance(hints, list):
                        return [str(h) for h in hints if h]
                except json.JSONDecodeError:
                    pass

            # 尝试找到 JSON 数组
            bracket_match = re.search(r"\[.*?\]", content, re.DOTALL)
            if bracket_match:
                try:
                    hints = json.loads(bracket_match.group(0))
                    if isinstance(hints, list):
                        return [str(h) for h in hints if h]
                except json.JSONDecodeError:
                    pass

        return []
