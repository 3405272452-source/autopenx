"""CTF 专用知识库 — 积累解题经验、Payload 模板和常见攻击模式。"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ChallengeProfile, ChallengeType

log = logging.getLogger(__name__)

# 内置数据文件路径
_DATA_DIR = Path(__file__).parent / "data"
_PAYLOADS_FILE = _DATA_DIR / "ctf_payloads.json"
_PATTERNS_FILE = _DATA_DIR / "ctf_patterns.json"


def re_split_words(text: str) -> List[str]:
    return [part for part in re.split(r"[^A-Za-z0-9_\u4e00-\u9fff:/.-]+", text or "") if part]


class CTFKnowledgeBase:
    """CTF 专用知识库，积累解题经验。

    支持记录解题过程、查询相似题目、获取 Payload 模板和常见攻击模式。
    数据可持久化到 JSON 文件，也可仅在内存中使用。
    """

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        """初始化知识库存储。

        Args:
            storage_path: 持久化存储的 JSON 文件路径。若为 None，则仅使用内存存储。
        """
        self.storage_path = storage_path
        # 保留 db_path 作为别名以兼容旧代码
        self.db_path = storage_path

        # 核心存储
        self.solve_records: List[Dict[str, Any]] = []
        self.attempt_records: List[Dict[str, Any]] = []
        self.payloads: Dict[str, Any] = {}
        self.patterns: Dict[str, List[Dict[str, Any]]] = {}

        # 从内置数据文件加载 Payload 和模式
        self._load_builtin_data()

        # 若指定了持久化路径，从文件加载历史记录
        if self.storage_path is not None:
            self._load_from_file()

    # ──────────────────────────────────────────────────────────────────────
    # 内部加载方法
    # ──────────────────────────────────────────────────────────────────────

    def _load_builtin_data(self) -> None:
        """从内置 JSON 数据文件加载 Payload 和模式。"""
        # 加载 Payload 模板
        if _PAYLOADS_FILE.exists():
            try:
                with _PAYLOADS_FILE.open(encoding="utf-8") as f:
                    self.payloads = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("无法加载内置 Payload 文件: %s", exc)
                self.payloads = {}
        else:
            log.warning("内置 Payload 文件不存在: %s", _PAYLOADS_FILE)

        # 加载攻击模式
        if _PATTERNS_FILE.exists():
            try:
                with _PATTERNS_FILE.open(encoding="utf-8") as f:
                    self.patterns = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("无法加载内置模式文件: %s", exc)
                self.patterns = {}
        else:
            log.warning("内置模式文件不存在: %s", _PATTERNS_FILE)
        self._seed_high_value_experience()

    def _load_from_file(self) -> None:
        """从持久化 JSON 文件加载解题记录。

        Uses the unified schema layer (knowledge_schema) to transparently
        handle both old-format and new-format files.
        """
        if self.storage_path is None or not self.storage_path.exists():
            return
        try:
            from .knowledge_schema import load_knowledge
            data = load_knowledge(self.storage_path)
            self.solve_records = data.get("solve_records", [])
            self.attempt_records = data.get("attempt_records", [])
            # 允许文件中覆盖内置 Payload 和模式
            if "payloads" in data:
                self.payloads.update(data["payloads"])
            if "patterns" in data and isinstance(data["patterns"], dict):
                # Only merge if patterns is a dict (builtin format)
                # The unified schema uses patterns as a list (KnowledgeLearner format)
                self.patterns.update(data["patterns"])
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("无法从文件加载知识库: %s", exc)

    def _persist(self) -> None:
        """将当前状态持久化到 JSON 文件。

        Preserves all unified schema fields (including new fields like
        route_weights, fast_payloads, fingerprint_route_map) so that
        other consumers (KnowledgeLearner, ExperienceWriter) don't lose
        their data when CTFKnowledgeBase writes.
        """
        if self.storage_path is None:
            return
        try:
            from .knowledge_schema import load_knowledge, save_knowledge

            # Load existing data to preserve fields we don't manage
            if self.storage_path.exists():
                existing = load_knowledge(self.storage_path)
            else:
                from .knowledge_schema import empty_knowledge
                existing = empty_knowledge()

            # Update only the fields CTFKnowledgeBase manages
            existing["solve_records"] = self.solve_records
            existing["attempt_records"] = self.attempt_records[-500:]

            save_knowledge(existing, self.storage_path)
        except OSError as exc:
            log.error("持久化知识库失败: %s", exc)

    # ──────────────────────────────────────────────────────────────────────
    # 公开 API
    # ──────────────────────────────────────────────────────────────────────

    def record_solve(self, profile: ChallengeProfile, solution: dict) -> None:
        """记录成功的解题过程。

        Args:
            profile: 题目画像，包含题型、技术栈、潜在漏洞等信息。
            solution: 解题详情字典，应包含 flag、target、steps_executed、
                      duration_ms、strategy_used 等字段。
        """
        record: Dict[str, Any] = {
            "timestamp": time.time(),
            "challenge_type": profile.challenge_type.value,
            "sub_type": profile.sub_type,
            "tech_stack": list(profile.tech_stack),
            "potential_vulns": list(profile.potential_vulns),
            "key_hints": list(profile.key_hints),
            "difficulty_estimate": profile.difficulty_estimate,
            "confidence": profile.confidence,
            # 解题详情
            "flag": solution.get("flag", ""),
            "target": solution.get("target", ""),
            "steps_executed": solution.get("steps_executed", 0),
            "duration_ms": solution.get("duration_ms", 0),
            "strategy_used": solution.get("strategy_used", ""),
        }
        self.solve_records.append(record)
        self._persist()

    def record_attempt(self, profile: ChallengeProfile, result: dict) -> None:
        """Record every completed CTF attempt, including failures and blockers."""
        record: Dict[str, Any] = {
            "timestamp": time.time(),
            "success": bool(result.get("success")),
            "challenge_type": profile.challenge_type.value,
            "sub_type": profile.sub_type,
            "tech_stack": list(profile.tech_stack),
            "potential_vulns": list(profile.potential_vulns),
            "key_hints": list(profile.key_hints),
            "target": result.get("target", ""),
            "flag": result.get("flag", ""),
            "error": result.get("error", ""),
            "steps_executed": result.get("steps_executed", result.get("iterations", 0)),
            "duration_ms": result.get("duration_ms", 0),
            "strategy_used": result.get("strategy_used", ""),
            "tools_used": result.get("tools_used", []),
            "lessons": result.get("lessons", []),
            "blockers": result.get("blockers", []),
        }
        self.attempt_records.append(record)
        if record["success"]:
            self.record_solve(profile, result)
        else:
            self._persist()

    def search_knowledge(self, query: str, *, challenge_type: str = "", limit: int = 8) -> List[Dict[str, Any]]:
        """Lightweight keyword search across built-in patterns and learned attempts."""
        terms = {term.lower() for term in re_split_words(query)}
        if challenge_type:
            terms.add(challenge_type.lower())
        candidates: List[Dict[str, Any]] = []

        def add_candidate(kind: str, item: Dict[str, Any], text: str) -> None:
            text_lower = text.lower()
            score = sum(1 for term in terms if term and term in text_lower)
            if score > 0:
                candidates.append({"kind": kind, "score": score, **item})

        for category, patterns in self.patterns.items():
            for pattern in patterns:
                add_candidate(
                    "pattern",
                    {"category": category, **pattern},
                    json.dumps(pattern, ensure_ascii=False) + " " + category,
                )
        for record in self.solve_records[-200:]:
            add_candidate("solve", record, json.dumps(record, ensure_ascii=False))
        for record in self.attempt_records[-200:]:
            add_candidate("attempt", record, json.dumps(record, ensure_ascii=False))
        candidates.sort(key=lambda item: item.get("score", 0), reverse=True)
        return candidates[:limit]

    def _seed_high_value_experience(self) -> None:
        """Seed compact high-signal patterns that the agent should always know."""
        web_patterns = self.patterns.setdefault("web", [])
        seeds = [
            {
                "name": "PHP Phar metadata deserialization via file_exists",
                "description": "file_exists(), unlink(), getimagesize(), exif_read_data(), or similar filesystem APIs on phar:// can deserialize Phar metadata before the target file operation.",
                "steps": [
                    "Find a controllable path reaching file_exists/unlink/getimagesize.",
                    "Find gadget classes with __destruct/__wakeup/__toString/__set.",
                    "Build a Phar with metadata containing the gadget object graph.",
                    "Upload/write the Phar bytes through any file-write primitive.",
                    "Trigger with phar://<uploaded-file> and then read the side effect or flag.",
                ],
                "success_rate": 0.72,
                "tools": ["phar_pdo_chain", "run_python", "http_request"],
                "indicators": ["phar://", "file_exists", "unlink", "__destruct", "__set", "Phar"],
            },
            {
                "name": "PDO FETCH_CLASS object instantiation chain",
                "description": "PDO::FETCH_CLASS | PDO::FETCH_PROPS_LATE (262152) can instantiate classes from query result columns; unknown columns can trigger __set.",
                "steps": [
                    "Check whether PDO connection options are controllable through serialization or config overwrite.",
                    "Point DSN to an attacker-controlled MySQL service if the target can connect out.",
                    "Make the first selected column the class name and order columns so needed properties are assigned before the __set-triggering unknown column.",
                    "Use __set/read gadget to copy /flag into a web-readable log path.",
                ],
                "success_rate": 0.60,
                "tools": ["phar_pdo_chain"],
                "indicators": ["PDO::ATTR_DEFAULT_FETCH_MODE", "FETCH_CLASS", "FETCH_PROPS_LATE", "262152", "__set"],
            },
            {
                "name": "Public source code first, exploit second",
                "description": "If a CTF provides source, static sink/source analysis should drive the exploit path before generic scanners.",
                "steps": [
                    "Extract nested archives and summarize routes/forms/superglobals.",
                    "Map user inputs to dangerous sinks.",
                    "Prefer a deterministic exploit chain over broad fuzzing.",
                    "Record exact blocker if infrastructure is required.",
                ],
                "success_rate": 0.85,
                "tools": ["file_analyze", "ctf_knowledge_search"],
                "indicators": ["source.zip", "src.zip", "Dockerfile", "源码", "attachment"],
            },
        ]
        existing = {pattern.get("name") for pattern in web_patterns}
        for seed in seeds:
            if seed["name"] not in existing:
                web_patterns.append(seed)

    def query_similar(
        self,
        challenge_type: "ChallengeType | ChallengeProfile",
        tech_stack: Optional[List[str]] = None,
        limit: int = 5,
    ) -> List[dict]:
        """查询相似题目的历史解法。

        支持两种调用方式:
        1. query_similar(challenge_type, tech_stack, limit) — 按题型和技术栈查询
        2. query_similar(profile, limit=5) — 按 ChallengeProfile 查询（兼容旧接口）

        相似度计算策略（优先级从高到低）：
        1. challenge_type 完全匹配 (+3 分)
        2. sub_type 完全匹配 (+2 分)
        3. tech_stack 重叠数量 (+1 分/项)
        4. potential_vulns 重叠数量 (+0.5 分/项)

        Args:
            challenge_type: ChallengeType 枚举值或 ChallengeProfile 实例。
            tech_stack: 技术栈列表（当第一个参数为 ChallengeType 时使用）。
            limit: 返回的最大记录数，默认 5。

        Returns:
            按相似度降序排列的历史解题记录列表（最多 limit 条）。
        """
        if not self.solve_records:
            return []

        # 解析参数：支持传入 ChallengeProfile 或 ChallengeType
        if isinstance(challenge_type, ChallengeProfile):
            profile = challenge_type
            target_type = profile.challenge_type.value
            target_sub = profile.sub_type.lower()
            target_stack = {s.lower() for s in profile.tech_stack}
            target_vulns = {v.lower() for v in profile.potential_vulns}
            # 如果 tech_stack 参数是 int，则作为 limit 使用（兼容旧调用方式）
            if isinstance(tech_stack, int):
                limit = tech_stack
        else:
            # challenge_type 是 ChallengeType 枚举
            target_type = challenge_type.value
            target_sub = ""
            target_stack = {s.lower() for s in (tech_stack or [])}
            target_vulns: set = set()

        scored: List[tuple] = []

        for record in self.solve_records:
            score = 0.0

            # 题型匹配
            if record.get("challenge_type") == target_type:
                score += 3.0

            # 子类型匹配
            rec_sub = record.get("sub_type", "").lower()
            if rec_sub and target_sub and rec_sub == target_sub:
                score += 2.0

            # 技术栈重叠
            rec_stack = {s.lower() for s in record.get("tech_stack", [])}
            overlap_stack = target_stack & rec_stack
            score += len(overlap_stack) * 1.0

            # 漏洞类型重叠
            rec_vulns = {v.lower() for v in record.get("potential_vulns", [])}
            overlap_vulns = target_vulns & rec_vulns
            score += len(overlap_vulns) * 0.5

            if score > 0:
                scored.append((score, record))

        # 按分数降序排列，取前 limit 条
        scored.sort(key=lambda x: x[0], reverse=True)
        return [rec for _, rec in scored[:limit]]

    def get_payloads(
        self,
        challenge_type: "ChallengeType | str",
        sub_type: str = "",
        tech_stack: Optional[List[str]] = None,
    ) -> List[str]:
        """获取指定类型的 Payload 模板列表。

        支持两种查询方式:
        1. 按 ChallengeType 查询 — 返回该题型下所有 Payload
        2. 按漏洞类型字符串查询 — 返回该漏洞类型的 Payload

        Args:
            challenge_type: ChallengeType 枚举值或漏洞类型字符串
                (如 'sqli', 'xss', 'lfi', 'ssti', 'xxe', 'cmdi', 'ssrf')。
            sub_type: 子类型过滤（如 'mysql', 'jinja2', 'generic'）。
            tech_stack: 技术栈过滤列表（可选）。

        Returns:
            Payload 字符串列表。若未找到对应类型，返回空列表。
        """
        # 确定查询键
        if isinstance(challenge_type, ChallengeType):
            # 按题型查询：收集该题型相关的所有 Payload
            type_key = challenge_type.value.lower()
            # 题型到漏洞类型的映射
            type_to_vulns = {
                "web": ["sqli", "xss", "lfi", "ssti", "xxe", "cmdi", "ssrf"],
                "pwn": [],
                "crypto": [],
                "misc": [],
                "reverse": [],
            }
            vuln_types = type_to_vulns.get(type_key, [])
            all_payloads: List[str] = []
            for vt in vuln_types:
                all_payloads.extend(self._get_payloads_for_vuln(vt, sub_type, tech_stack))
            return all_payloads
        else:
            # 按漏洞类型字符串查询
            return self._get_payloads_for_vuln(str(challenge_type), sub_type, tech_stack)

    def _get_payloads_for_vuln(
        self,
        vuln_type: str,
        sub_type: str = "",
        tech_stack: Optional[List[str]] = None,
    ) -> List[str]:
        """获取指定漏洞类型的 Payload 模板列表（内部方法）。

        Args:
            vuln_type: 漏洞类型字符串。
            sub_type: 子类型过滤。
            tech_stack: 技术栈过滤列表。

        Returns:
            Payload 字符串列表。
        """
        vuln_lower = vuln_type.lower()
        vuln_data = self.payloads.get(vuln_lower)
        if not vuln_data:
            return []

        # 若 vuln_data 是列表，直接返回
        if isinstance(vuln_data, list):
            return list(vuln_data)

        # 若 vuln_data 是字典（按子类型分组）
        if isinstance(vuln_data, dict):
            # 如果指定了 sub_type，优先返回匹配的子类型
            if sub_type:
                sub_lower = sub_type.lower()
                matched = vuln_data.get(sub_lower)
                if matched and isinstance(matched, list):
                    return list(matched)
                # 尝试部分匹配
                for key, payloads in vuln_data.items():
                    if sub_lower in key.lower() or key.lower() in sub_lower:
                        if isinstance(payloads, list):
                            return list(payloads)

            # 如果指定了 tech_stack，按技术栈过滤
            if tech_stack:
                stack_lower = [t.lower() for t in tech_stack]
                matched_payloads: List[str] = []
                for key, payloads in vuln_data.items():
                    if any(t in key.lower() for t in stack_lower):
                        if isinstance(payloads, list):
                            matched_payloads.extend(payloads)
                if matched_payloads:
                    return matched_payloads

            # 无匹配，返回所有 Payload（展平）
            all_payloads: List[str] = []
            for payloads in vuln_data.values():
                if isinstance(payloads, list):
                    all_payloads.extend(payloads)
            return all_payloads

        return []

    def get_common_patterns(self, challenge_type: ChallengeType) -> List[dict]:
        """获取指定题型的常见解题模式。

        Args:
            challenge_type: CTF 题型枚举值。

        Returns:
            解题模式列表，每个模式包含 name、description、steps、success_rate 等字段。
        """
        type_key = challenge_type.value.lower()
        return list(self.patterns.get(type_key, []))


class CTFKnowledgeRetriever:
    """三阶段知识检索器。

    实现三阶段检索策略：
    1. 阶段 1: 查询相似的历史解题记录 (past solves)
    2. 阶段 2: 获取相关的 Payload 模板
    3. 阶段 3: 获取常见攻击模式
    """

    def __init__(self, knowledge_base: CTFKnowledgeBase) -> None:
        """初始化检索器。

        Args:
            knowledge_base: CTFKnowledgeBase 实例。
        """
        self.kb = knowledge_base

    def retrieve(self, profile: ChallengeProfile) -> dict:
        """执行三阶段知识检索。

        Stage 1: Query similar past solves
        Stage 2: Get relevant payloads
        Stage 3: Get common patterns

        Args:
            profile: 当前题目画像。

        Returns:
            包含三个阶段检索结果的字典:
            {
                "similar_solves": [...],
                "payloads": [...],
                "patterns": [...],
            }
        """
        # ── 阶段 1: 查询相似的历史解题记录 ──────────────────────────────
        similar_solves = self.kb.query_similar(
            profile.challenge_type,
            tech_stack=list(profile.tech_stack),
            limit=5,
        )

        # ── 阶段 2: 获取相关的 Payload 模板 ─────────────────────────────
        payloads: List[str] = []
        # 按题型获取 Payload
        type_payloads = self.kb.get_payloads(
            profile.challenge_type,
            sub_type=profile.sub_type,
            tech_stack=list(profile.tech_stack),
        )
        payloads.extend(type_payloads)

        # 如果有潜在漏洞，也按漏洞类型获取
        for vuln in profile.potential_vulns:
            vuln_payloads = self.kb.get_payloads(
                vuln,
                sub_type=profile.sub_type,
                tech_stack=list(profile.tech_stack),
            )
            # 去重添加
            for p in vuln_payloads:
                if p not in payloads:
                    payloads.append(p)

        # ── 阶段 3: 获取常见攻击模式 ───────────────────────────────────
        patterns = self.kb.get_common_patterns(profile.challenge_type)

        return {
            "similar_solves": similar_solves,
            "payloads": payloads,
            "patterns": patterns,
        }
