"""Flag 识别、提取与验证引擎。

本模块实现 FlagEngine 类，负责从工具输出中自动识别、提取和验证
各种格式的 CTF Flag。支持明文扫描、多种编码解码、二进制数据扫描，
以及动态注册新的 Flag 格式。
"""
from __future__ import annotations

import base64
import codecs
import re
import urllib.parse
from typing import List, Optional, Set, Tuple

from .models import FlagCandidate


class FlagEngine:
    """Flag 识别、提取与验证引擎。

    多层扫描策略：明文正则匹配 → 编码解码后扫描 → 二进制字符串提取。
    支持去重、置信度排序和动态格式注册。

    设计原则:
        - 多层扫描: 明文 → 编码解码 → 二进制字符串提取
        - 去重: 相同 Flag 值只保留置信度最高的候选
        - 可扩展: 支持动态注册新的 Flag 格式
    """

    # 默认支持的 Flag 格式: (名称, 正则表达式)
    DEFAULT_FORMATS: List[Tuple[str, str]] = [
        ("standard", r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?]+\}"),
        ("ctf_prefix", r"CTF\{[^}]+\}"),
        ("hctf", r"hctf\{[^}]+\}"),
        ("sctf", r"sctf\{[^}]+\}"),
        ("hitcon", r"hitcon\{[^}]+\}"),
        ("bctf", r"bctf\{[^}]+\}"),
        ("generic_brace", r"[a-zA-Z]+\{[a-zA-Z0-9_\-]+\}"),
        ("md5_hash", r"[a-f0-9]{32}"),
        ("sha256_hash", r"[a-f0-9]{64}"),
        (
            "uuid_flag",
            r"flag-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        ),
    ]

    # 支持的编码方式
    ENCODINGS: List[str] = ["base64", "base32", "hex", "url", "rot13"]

    def __init__(
        self,
        flag_formats: Optional[List[str]] = None,
        encoding_detection: bool = True,
    ) -> None:
        """初始化 Flag 引擎。

        Args:
            flag_formats: 自定义 Flag 格式正则列表。若为 None 则使用默认格式。
            encoding_detection: 是否启用编码自动检测，默认 True。

        Raises:
            ValueError: 当 flag_formats 中包含不合法的正则表达式时。
        """
        if flag_formats is not None:
            self._formats: List[Tuple[str, str]] = [
                (f"custom_{i}", pattern)
                for i, pattern in enumerate(flag_formats)
            ]
        else:
            self._formats = list(self.DEFAULT_FORMATS)

        self._encoding_detection = encoding_detection

        # Compile all regex patterns to verify they're valid
        for name, pattern in self._formats:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(
                    f"无效的正则表达式 '{pattern}' (格式名: {name}): {e}"
                ) from e

    def scan(self, content: str) -> List[FlagCandidate]:
        """扫描文本内容，返回所有可能的 Flag 候选。

        使用已注册的所有格式正则对明文内容进行匹配，
        结果按置信度降序排列且无重复值。

        Args:
            content: 待扫描的文本内容。

        Returns:
            按置信度降序排列的 FlagCandidate 列表，无重复值。
        """
        candidates: List[FlagCandidate] = []
        seen: Set[str] = set()

        # 置信度映射：特定命名格式 → 对应置信度
        HIGH_CONFIDENCE_FORMATS = {
            "standard", "ctf_prefix", "hctf", "sctf",
            "hitcon", "bctf", "uuid_flag",
        }
        HASH_FORMATS = {"md5_hash", "sha256_hash"}

        for name, pattern in self._formats:
            for match in re.finditer(pattern, content):
                value = match.group(0)
                if value in seen:
                    continue
                seen.add(value)

                # 计算置信度
                if name in HIGH_CONFIDENCE_FORMATS:
                    confidence = 1.0
                elif name == "generic_brace":
                    confidence = 0.6
                elif name in HASH_FORMATS:
                    confidence = 0.5
                else:
                    # custom formats (custom_0, custom_1, etc.)
                    confidence = 0.9

                # 提取上下文: 匹配位置前后各 50 个字符
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end]

                candidates.append(FlagCandidate(
                    value=value,
                    source="text_scan",
                    confidence=confidence,
                    encoding="plaintext",
                    context=context,
                ))

        # 按置信度降序排列
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def decode_and_scan(self, content: str) -> List[FlagCandidate]:
        """尝试多种解码后扫描 Flag。

        对内容依次尝试 Base64、Base32、Hex、URL编码、ROT13 解码，
        解码成功后调用 scan() 进行 Flag 匹配。编码后发现的 Flag
        置信度乘以 0.9 系数。

        Args:
            content: 待解码和扫描的文本内容。

        Returns:
            按置信度降序排列的 FlagCandidate 列表，标注了原始编码方式。
        """
        candidates: List[FlagCandidate] = []

        for encoding in self.ENCODINGS:
            try:
                decoded = self._decode(content, encoding)
                if decoded:
                    sub_candidates = self.scan(decoded)
                    for c in sub_candidates:
                        c.encoding = encoding
                        c.confidence *= 0.9
                    candidates.extend(sub_candidates)
            except (ValueError, UnicodeDecodeError):
                continue

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def scan_binary(self, data: bytes) -> List[FlagCandidate]:
        """扫描二进制数据中的 Flag。

        从二进制数据中提取可打印字符串，然后对提取的字符串
        进行 Flag 扫描。

        Args:
            data: 待扫描的二进制数据。

        Returns:
            按置信度降序排列的 FlagCandidate 列表。
        """
        # 提取可打印 ASCII 字符串（最小长度 4）
        strings = re.findall(rb"[\x20-\x7e]{4,}", data)
        joined = " ".join(s.decode("ascii") for s in strings)

        candidates = self.scan(joined)
        for c in candidates:
            c.source = "binary_scan"

        return candidates

    def validate(self, candidate: str, expected_format: str) -> bool:
        """验证候选 Flag 是否符合预期格式。

        Args:
            candidate: 候选 Flag 字符串。
            expected_format: 预期的正则表达式格式。

        Returns:
            True 当候选 Flag 完全匹配预期格式时。
        """
        try:
            return re.fullmatch(expected_format, candidate) is not None
        except re.error:
            return False

    def add_format(self, name: str, pattern: str) -> None:
        """注册新的 Flag 格式。

        Args:
            name: 格式名称标识。
            pattern: 正则表达式模式字符串。

        Raises:
            ValueError: 当 pattern 不是合法的正则表达式时。
        """
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(
                f"无效的正则表达式 '{pattern}' (格式名: {name}): {e}"
            ) from e
        self._formats.append((name, pattern))

    def _decode(self, content: str, encoding: str) -> Optional[str]:
        """尝试以指定编码解码内容。

        内部辅助方法，对给定内容尝试指定编码方式的解码。
        解码失败时返回 None。

        Args:
            content: 待解码的文本内容。
            encoding: 编码方式（base64, base32, hex, url, rot13）。

        Returns:
            解码后的字符串，解码失败时返回 None。
        """
        try:
            if encoding == "base64":
                # 提取可能的 Base64 片段
                b64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
                for match in re.finditer(b64_pattern, content):
                    try:
                        decoded = base64.b64decode(match.group(0)).decode(
                            "utf-8", errors="ignore"
                        )
                        if decoded and any(c.isprintable() for c in decoded):
                            return decoded
                    except Exception:
                        continue
            elif encoding == "base32":
                # 提取可能的 Base32 片段
                b32_pattern = r"[A-Z2-7]{16,}={0,6}"
                for match in re.finditer(b32_pattern, content):
                    try:
                        decoded = base64.b32decode(match.group(0)).decode(
                            "utf-8", errors="ignore"
                        )
                        if decoded and any(c.isprintable() for c in decoded):
                            return decoded
                    except Exception:
                        continue
            elif encoding == "hex":
                # 提取可能的 Hex 片段
                hex_pattern = r"[0-9a-fA-F]{20,}"
                for match in re.finditer(hex_pattern, content):
                    try:
                        return bytes.fromhex(match.group(0)).decode(
                            "utf-8", errors="ignore"
                        )
                    except Exception:
                        continue
            elif encoding == "url":
                return urllib.parse.unquote(content)
            elif encoding == "rot13":
                return codecs.decode(content, "rot_13")
        except Exception:
            return None
        return None
