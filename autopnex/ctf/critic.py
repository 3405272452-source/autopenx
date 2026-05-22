"""Critic / Verifier – read-only review agent for CTF sessions.

The Critic does **not** execute tools or mutate challenge state.
It only reads the SharedJournal, StrategyEngine summary, and FuseController
state, then writes recommendations to next_actions.md and hypotheses.jsonl.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from .fuse_controller import FuseController
from .shared_journal import HypothesisRecord, SharedJournal
from .strategy import StrategyEngine

log = logging.getLogger("autopnex.ctf.critic")


class CriticReview:
    """Structured output of a Critic review."""

    def __init__(self) -> None:
        self.most_likely_route: str = ""
        self.abandon_routes: List[str] = []
        self.is_stuck: bool = False
        self.blocker_is_real: bool = True
        self.recommended_next_action: str = ""
        self.confidence: float = 0.0
        # New optional fields (backward compatible)
        self.reasoning: str = ""        # AI Critic reasoning process
        self.source: str = "heuristic"  # "ai" or "heuristic"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "most_likely_route": self.most_likely_route,
            "abandon_routes": self.abandon_routes,
            "is_stuck": self.is_stuck,
            "blocker_is_real": self.blocker_is_real,
            "recommended_next_action": self.recommended_next_action,
            "confidence": self.confidence,
        }
        if self.reasoning:
            d["reasoning"] = self.reasoning
        if self.source != "heuristic":
            d["source"] = self.source
        return d


class Critic:
    """Read-only Critic that audits a CTF session and gives actionable advice."""

    # How many recent attempts to inspect for repetition
    REPETITION_WINDOW = 6

    def __init__(self) -> None:
        pass

    def review(
        self,
        journal: SharedJournal,
        strategy: StrategyEngine,
        fuse: FuseController,
    ) -> CriticReview:
        """Run a full read-only review and return structured advice."""
        review = CriticReview()

        # 1. Most likely route based on evidence scores
        review.most_likely_route = self._pick_best_route(journal, strategy)

        # 2. Detect stuck state
        review.is_stuck = self._detect_stuck(journal, strategy)

        # 3. Detect abandoned routes (exhausted + low best_score)
        review.abandon_routes = self._detect_abandon_routes(strategy)

        # 4. Check whether the latest blocker is real
        review.blocker_is_real = self._assess_latest_blocker(journal)

        # 5. Recommend exactly one next action
        review.recommended_next_action = self._recommend_action(
            review, journal, strategy, fuse
        )

        # 6. Overall confidence
        review.confidence = self._compute_confidence(journal, strategy, review)

        return review

    def write_to_journal(
        self,
        review: CriticReview,
        journal: SharedJournal,
    ) -> None:
        """Persist review results into SharedJournal (write permission limited)."""
        # Write hypothesis for the recommended route
        journal.log_hypothesis(
            HypothesisRecord(
                id=f"critic_{int(time.time())}",
                text=f"Critic 推荐: {review.recommended_next_action}",
                confidence=review.confidence,
                status="active",
                route=review.most_likely_route,
            )
        )

        # Write next_actions.md
        lines: List[str] = [
            "## Critic 审查报告",
            f"- **最可能路线**: {review.most_likely_route}",
            f"- **是否卡住**: {'是' if review.is_stuck else '否'}",
            f"- **应放弃路线**: {', '.join(review.abandon_routes) or '无'}",
            f"- **最新 blocker 是否真实**: {'是' if review.blocker_is_real else '否（疑似误判）'}",
            f"- **唯一推荐下一步**: {review.recommended_next_action}",
            f"- **审查置信度**: {review.confidence:.2f}",
        ]
        journal.write_next_actions("\n".join(lines), role="critic")

    # -- internal analysis ------------------------------------------------

    def _pick_best_route(self, journal: SharedJournal, strategy: StrategyEngine) -> str:
        evidence = journal.evidence_cards
        if not evidence:
            return strategy._current_route or "unknown"

        # Aggregate scores per route
        route_scores: Dict[str, float] = {}
        for ev in evidence:
            route_scores[ev.route] = route_scores.get(ev.route, 0.0) + ev.confidence

        # Also factor strategy route best_score
        for rid, budget in strategy._routes.items():
            route_scores[rid] = route_scores.get(rid, 0.0) + budget.best_score

        if not route_scores:
            return strategy._current_route or "unknown"
        return max(route_scores, key=route_scores.get)

    def _detect_stuck(self, journal: SharedJournal, strategy: StrategyEngine) -> bool:
        attempts = journal.attempts
        if len(attempts) < self.REPETITION_WINDOW:
            return False

        recent = attempts[-self.REPETITION_WINDOW:]
        # Stuck if no new_info in recent attempts
        if all(not a.new_info for a in recent):
            return True

        # Stuck if same tool repeated too many times
        tools = [a.tool for a in recent]
        if len(set(tools)) == 1:
            return True

        # Stuck if route budget exhausted and no next route
        if strategy._current_route:
            budget = strategy._routes.get(strategy._current_route)
            if budget and budget.exhausted and not strategy.suggest_next_route():
                return True

        return False

    def _detect_abandon_routes(self, strategy: StrategyEngine) -> List[str]:
        abandoned: List[str] = []
        for rid, budget in strategy._routes.items():
            if budget.exhausted and budget.best_score < 0.3:
                abandoned.append(rid)
        return abandoned

    def _assess_latest_blocker(self, journal: SharedJournal) -> bool:
        blockers = journal.blockers
        if not blockers:
            return True  # No blocker means no false blocker
        latest = blockers[-1]
        # A blocker is "real" if it has concrete evidence beyond its own id
        return len(latest.evidence) > 30  # heuristic: some real payload / error text

    def _recommend_action(
        self,
        review: CriticReview,
        journal: SharedJournal,
        strategy: StrategyEngine,
        fuse: FuseController,
    ) -> str:
        if review.is_stuck:
            next_route = strategy.suggest_next_route()
            if next_route:
                return f"切换到下一路线 '{next_route}'，避免在 '{strategy._current_route}' 上继续空转"
            return "所有路线尝试完毕，建议终止并输出 blocker"

        if not review.blocker_is_real:
            return "最新 blocker 证据不足，建议重新验证并继续当前路线"

        if review.most_likely_route:
            return f"继续深挖路线 '{review.most_likely_route}'，聚焦最高置信度证据"

        return "进行更全面的信息收集（侦察）后再决定主攻方向"

    def _compute_confidence(
        self,
        journal: SharedJournal,
        strategy: StrategyEngine,
        review: CriticReview,
    ) -> float:
        # Simple heuristic: more evidence and clear best route = higher confidence
        score = 0.3
        score += min(len(journal.evidence_cards) * 0.05, 0.4)
        if review.most_likely_route:
            score += 0.15
        if not review.is_stuck:
            score += 0.15
        return min(score, 1.0)


# ---------------------------------------------------------------------------
# AI Critic - LLM-driven intelligent reviewer
# ---------------------------------------------------------------------------


class AICritic:
    """基于独立 LLM 调用的智能审查器。

    当主代理卡住时，AICritic 使用独立的 LLM 调用分析当前会话状态，
    提供"第二意见"帮助突破思维定式。失败时回退到启发式 Critic。
    """

    def __init__(self, llm_config: Optional[Dict[str, Any]] = None):
        self._heuristic_fallback = Critic()  # 现有规则审查器
        self._llm_config = llm_config or {}

    async def review(
        self,
        journal: SharedJournal,
        strategy: StrategyEngine,
        fuse: FuseController,
    ) -> CriticReview:
        """执行 AI 审查，失败时回退到启发式审查。

        Flow:
        1. Build prompt from journal/strategy/fuse state
        2. Call independent LLM via LLMClient
        3. Parse response into CriticReview
        4. On ANY failure, fall back to heuristic Critic and log the event
        """
        try:
            prompt = self._build_prompt(journal, strategy, fuse)
            response_text = self._call_llm(prompt)
            review = self._parse_response(response_text)
            review.source = "ai"
            return review
        except Exception as exc:
            log.warning(
                "AICritic LLM call failed, falling back to heuristic: %s", exc
            )
            review = self._heuristic_fallback.review(journal, strategy, fuse)
            review.source = "heuristic"
            return review

    def _call_llm(self, prompt: str) -> str:
        """调用独立 LLM 获取审查结果。

        使用项目的 LLMClient，创建独立实例避免与主 Agent 会话冲突。
        """
        from autopnex.orchestrator.llm_client import LLMClient, LLMError

        # Use llm_config overrides if provided, otherwise use project defaults
        api_key = self._llm_config.get("api_key")
        base_url = self._llm_config.get("base_url")
        model = self._llm_config.get("model")

        client = LLMClient(api_key=api_key, base_url=base_url, model=model)

        if not client.enabled:
            raise LLMError("LLM disabled: no API key configured for AICritic")

        messages = [
            {"role": "system", "content": "你是一个 CTF 安全竞赛的独立审查专家。请基于提供的信息进行分析，输出 JSON 格式的审查结果。"},
            {"role": "user", "content": prompt},
        ]

        result = client.chat(
            messages=messages,
            temperature=0.3,
            max_tokens=1200,
        )

        content = result.get("content", "")
        if not content:
            raise ValueError("LLM returned empty response")

        return content

    def _build_prompt(
        self,
        journal: SharedJournal,
        strategy: StrategyEngine,
        fuse: FuseController,
    ) -> str:
        """构建 LLM 审查提示词。

        组装 SharedJournal 摘要、当前路线、证据卡片、blocker 信息，
        生成结构化的提示词供独立 LLM 调用使用。
        """
        sections: List[str] = []

        # --- System instruction ---
        sections.append(
            "你是一个 CTF 安全竞赛的独立审查专家。你的任务是分析当前攻击会话的状态，"
            "判断主代理是否卡住，并给出具体的下一步建议。\n"
            "请基于以下信息进行分析，输出 JSON 格式的审查结果。"
        )

        # --- Section 1: Journal Summary ---
        sections.append("\n## 会话摘要")
        summary = journal.get_summary()
        sections.append(f"- Session ID: {summary['session_id']}")
        sections.append(f"- 总尝试次数: {summary['attempts_count']}")
        sections.append(f"- 总证据数: {summary['evidence_count']}")
        sections.append(f"- 总假设数: {summary['hypotheses_count']}")
        sections.append(f"- 总阻塞数: {summary['blockers_count']}")

        # --- Section 2: Current Route ---
        sections.append("\n## 当前路线")
        strategy_summary = strategy.get_summary()
        current_route = strategy_summary.get("current_route") or "未设定"
        sections.append(f"- 当前攻击路线: {current_route}")
        sections.append(
            f"- 总消耗: {strategy_summary['total_cost']}/{strategy_summary['max_cost']}"
        )
        sections.append(
            f"- 预算是否耗尽: {'是' if strategy_summary['budget_exhausted'] else '否'}"
        )

        # Route details
        routes_info = strategy_summary.get("routes", {})
        if routes_info:
            sections.append("\n### 路线预算详情")
            for rid, rinfo in routes_info.items():
                status = "已耗尽" if rinfo.get("exhausted") else "可用"
                sections.append(
                    f"  - {rid}: {rinfo['attempts']}/{rinfo['max_attempts']} 次尝试, "
                    f"最高分 {rinfo['best_score']:.3f}, 状态={status}"
                )

        # --- Section 3: Evidence Cards ---
        sections.append("\n## 证据卡片（最近 5 条）")
        recent_evidence = journal.latest_evidence(5)
        if recent_evidence:
            for ev in recent_evidence:
                sections.append(
                    f"  - [{ev.route}] {ev.summary} "
                    f"(来源={ev.source}, 置信度={ev.confidence:.2f}, "
                    f"建议下一步={ev.next_action})"
                )
        else:
            sections.append("  （暂无证据）")

        # --- Section 4: Blocker Information ---
        sections.append("\n## 阻塞信息")
        recent_blockers = journal.latest_blockers(3)
        if recent_blockers:
            for b in recent_blockers:
                resolved_str = "已解决" if b.resolved else "未解决"
                sections.append(
                    f"  - [{b.severity}] {b.description} "
                    f"(路线={b.route}, 状态={resolved_str})"
                )
                if b.evidence:
                    # Truncate long evidence to keep prompt manageable
                    evidence_preview = b.evidence[:200]
                    if len(b.evidence) > 200:
                        evidence_preview += "..."
                    sections.append(f"    证据: {evidence_preview}")
        else:
            sections.append("  （暂无阻塞）")

        # --- Section 5: Recent Attempts ---
        sections.append("\n## 最近尝试记录（最近 6 条）")
        recent_attempts = journal.latest_attempts(6)
        if recent_attempts:
            for a in recent_attempts:
                new_info_str = "有新信息" if a.new_info else "无新信息"
                success_str = "成功" if a.success else "失败"
                sections.append(
                    f"  - 迭代{a.iteration}: 工具={a.tool}, 路线={a.route}, "
                    f"{success_str}, {new_info_str}"
                )
        else:
            sections.append("  （暂无尝试记录）")

        # --- Section 6: Hypotheses ---
        sections.append("\n## 当前假设")
        recent_hypotheses = journal.latest_hypotheses(5)
        if recent_hypotheses:
            for h in recent_hypotheses:
                sections.append(
                    f"  - [{h.status}] {h.text} (置信度={h.confidence:.2f}, 路线={h.route})"
                )
        else:
            sections.append("  （暂无假设）")

        # --- Section 7: Fuse Controller State ---
        sections.append("\n## 熔断器状态")
        sections.append(f"- 重复动作计数: {fuse._repeat_count}")
        sections.append(f"- 无证据轮数: {fuse._rounds_without_evidence}")
        sections.append(f"- 空转轮数: {fuse._idle_rounds}")
        sections.append(f"- 错误重复计数: {fuse._error_repeat_count}")

        # --- Output format instruction ---
        sections.append("\n## 输出格式要求")
        sections.append(
            "请输出以下 JSON 格式的审查结果：\n"
            "```json\n"
            "{\n"
            '  "most_likely_route": "最可能成功的攻击路线",\n'
            '  "abandon_routes": ["应放弃的路线列表"],\n'
            '  "is_stuck": true/false,\n'
            '  "blocker_is_real": true/false,\n'
            '  "recommended_next_action": "具体的下一步操作建议",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "reasoning": "你的分析推理过程"\n'
            "}\n"
            "```"
        )

        return "\n".join(sections)

    def _parse_response(self, response: str) -> CriticReview:
        """解析 LLM 响应为 CriticReview。

        Handles:
        - Raw JSON responses
        - JSON wrapped in markdown code blocks (```json ... ```)
        - Partial/malformed JSON (raises ValueError for fallback)
        """
        # Strip markdown code block wrapping if present
        json_str = self._extract_json_from_response(response)

        try:
            data = json.loads(json_str)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Failed to parse LLM response as JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"Expected JSON object, got {type(data).__name__}")

        review = CriticReview()
        review.source = "ai"

        # Map JSON fields to CriticReview attributes
        review.most_likely_route = str(data.get("most_likely_route", ""))
        review.abandon_routes = list(data.get("abandon_routes", []))
        review.is_stuck = bool(data.get("is_stuck", False))
        review.blocker_is_real = bool(data.get("blocker_is_real", True))
        review.recommended_next_action = str(data.get("recommended_next_action", ""))
        review.reasoning = str(data.get("reasoning", ""))

        # Parse confidence, clamp to [0.0, 1.0]
        try:
            confidence = float(data.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        review.confidence = max(0.0, min(1.0, confidence))

        # Validate that we have at least a recommended action
        if not review.recommended_next_action:
            raise ValueError("LLM response missing 'recommended_next_action' field")

        return review

    @staticmethod
    def _extract_json_from_response(response: str) -> str:
        """从 LLM 响应中提取 JSON 字符串，处理 markdown 代码块包裹。"""
        text = response.strip()

        # Try to extract from markdown code block: ```json ... ``` or ``` ... ```
        code_block_pattern = re.compile(
            r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL
        )
        match = code_block_pattern.search(text)
        if match:
            return match.group(1).strip()

        # Try to find raw JSON object in the response
        # Look for the first { ... } block
        brace_start = text.find("{")
        if brace_start != -1:
            # Find matching closing brace
            depth = 0
            for i in range(brace_start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        return text[brace_start : i + 1]

        # Return as-is and let json.loads handle the error
        return text
