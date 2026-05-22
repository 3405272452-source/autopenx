"""Fuse Controller - circuit-breaker for CTF agent loops.

Reads StrategyEngine, SharedJournal, and ActionRuntime results and decides
whether to let the agent continue, switch routes, or stop entirely.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .shared_journal import BlockerRecord, SharedJournal
from .strategy import StrategyEngine

log = logging.getLogger("autopnex.ctf.fuse_controller")


# ---------------------------------------------------------------------------
# Decision dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FuseDecision:
    """Outcome of a fuse check."""

    level: str          # soft | route | hard | none
    fuse_type: str      # repeat_action | no_evidence | route_budget | error_pattern | idle_spin
    reason: str         # human-readable Chinese reason
    route_id: str = ""
    suggestion: str = ""  # what to do next

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "fuse_type": self.fuse_type,
            "reason": self.reason,
            "route_id": self.route_id,
            "suggestion": self.suggestion,
        }


# ---------------------------------------------------------------------------
# FuseController
# ---------------------------------------------------------------------------

class FuseController:
    """Monitors agent behaviour and triggers circuit-breakers.

    Thresholds (all configurable):
    * repeat_threshold    – consecutive identical (tool, args_hash)
    * no_evidence_rounds  – rounds without new evidence card
    * error_repeat_limit  – consecutive identical error_type
    * idle_rounds_limit   – rounds with no tool call or similar LLM output
    """

    def __init__(
        self,
        repeat_threshold: int = 2,
        no_evidence_rounds: int = 4,
        error_repeat_limit: int = 3,
        idle_rounds_limit: int = 3,
    ) -> None:
        self.repeat_threshold = repeat_threshold
        self.no_evidence_rounds = no_evidence_rounds
        self.error_repeat_limit = error_repeat_limit
        self.idle_rounds_limit = idle_rounds_limit

        # Internal state
        self._last_action_hash: str = ""
        self._repeat_count: int = 0
        self._last_error_type: str = ""
        self._error_repeat_count: int = 0
        self._rounds_without_evidence: int = 0
        self._idle_rounds: int = 0
        self._last_evidence_count: int = 0
        self._last_llm_hash: str = ""

    def check(
        self,
        strategy: StrategyEngine,
        journal: SharedJournal,
        action_result: Optional[Any] = None,
        iteration: int = 0,
        llm_content: str = "",
        tool_calls_count: int = 0,
        tool_name: str = "",
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> FuseDecision:
        """Run all fuse checks and return the highest-priority decision."""

        # 1. 重复动作熔断
        decision = self._check_repeat_action(strategy, action_result, tool_name, tool_args or {})
        if decision.level != "none":
            return decision

        # 2. 无新证据熔断
        decision = self._check_no_evidence(journal)
        if decision.level != "none":
            return decision

        # 3. 路线预算熔断 (already tracked by strategy, but we elevate it here)
        decision = self._check_route_budget(strategy)
        if decision.level != "none":
            return decision

        # 4. 错误类型熔断
        decision = self._check_error_pattern(action_result)
        if decision.level != "none":
            return decision

        # 5. 模型空转熔断
        decision = self._check_idle_spin(llm_content, tool_calls_count)
        if decision.level != "none":
            return decision

        return FuseDecision(level="none", fuse_type="none", reason="")

    # -- individual checks ------------------------------------------------

    def _check_repeat_action(
        self,
        strategy: StrategyEngine,
        action_result: Optional[Any],
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> FuseDecision:
        if not tool_name:
            return FuseDecision(level="none", fuse_type="none", reason="")

        # Build hash from tool_name + normalized args (aligns with StrategyEngine dedup)
        args_hash = StrategyEngine._hash_args(tool_name, tool_args)
        if args_hash == self._last_action_hash and args_hash:
            self._repeat_count += 1
        else:
            self._last_action_hash = args_hash
            self._repeat_count = 1

        if self._repeat_count >= self.repeat_threshold:
            return FuseDecision(
                level="soft",
                fuse_type="repeat_action",
                reason=f"连续 {self._repeat_count} 次执行了相同动作（参数哈希 {args_hash[:8]}...），禁止重复",
                suggestion="修改参数、切换路线或请求 LLM 生成新策略",
            )
        return FuseDecision(level="none", fuse_type="none", reason="")

    def _check_no_evidence(self, journal: SharedJournal) -> FuseDecision:
        current = len(journal.evidence_cards)
        if current == self._last_evidence_count:
            self._rounds_without_evidence += 1
        else:
            self._last_evidence_count = current
            self._rounds_without_evidence = 0

        if self._rounds_without_evidence >= self.no_evidence_rounds:
            return FuseDecision(
                level="route",
                fuse_type="no_evidence",
                reason=f"连续 {self._rounds_without_evidence} 轮未产生新证据",
                suggestion="暂停当前路线，触发 Critic 审查或切换到相邻路线",
            )
        return FuseDecision(level="none", fuse_type="none", reason="")

    def _check_route_budget(self, strategy: StrategyEngine) -> FuseDecision:
        route = strategy._current_route
        if not route:
            return FuseDecision(level="none", fuse_type="none", reason="")

        budget = strategy._routes.get(route)
        if budget and budget.exhausted:
            next_route = strategy.suggest_next_route()
            if next_route:
                return FuseDecision(
                    level="route",
                    fuse_type="route_budget",
                    reason=f"路线 '{route}' 预算已耗尽（已尝试 {budget.attempts}/{budget.max_attempts}）",
                    route_id=route,
                    suggestion=f"切换到下一路线: {next_route}",
                )
            else:
                return FuseDecision(
                    level="hard",
                    fuse_type="route_budget",
                    reason=f"所有可用路线预算均已耗尽，最后路线: '{route}'",
                    route_id=route,
                    suggestion="终止当前任务并输出真实 blocker",
                )
        return FuseDecision(level="none", fuse_type="none", reason="")

    def _check_error_pattern(self, action_result: Optional[Any]) -> FuseDecision:
        if action_result is None:
            return FuseDecision(level="none", fuse_type="none", reason="")

        error_type = getattr(action_result, "error_type", None) or ""
        if not error_type:
            self._error_repeat_count = 0
            self._last_error_type = ""
            return FuseDecision(level="none", fuse_type="none", reason="")

        if error_type == self._last_error_type:
            self._error_repeat_count += 1
        else:
            self._last_error_type = error_type
            self._error_repeat_count = 1

        if self._error_repeat_count >= self.error_repeat_limit:
            if error_type in ("environment", "network"):
                level = "route"
            else:
                level = "soft"
            return FuseDecision(
                level=level,
                fuse_type="error_pattern",
                reason=f"连续 {self._error_repeat_count} 次出现同类错误 '{error_type}'",
                suggestion="转入环境修复、降级工具或切换路线",
            )
        return FuseDecision(level="none", fuse_type="none", reason="")

    def _check_idle_spin(self, llm_content: str, tool_calls_count: int) -> FuseDecision:
        if tool_calls_count == 0:
            self._idle_rounds += 1
        else:
            # Reset if there were tool calls; also compare content hash for similarity
            content_hash = self._hash_text(llm_content)
            if content_hash == self._last_llm_hash:
                self._idle_rounds += 1
            else:
                self._idle_rounds = 0
            self._last_llm_hash = content_hash

        if self._idle_rounds >= self.idle_rounds_limit:
            return FuseDecision(
                level="soft",
                fuse_type="idle_spin",
                reason=f"连续 {self._idle_rounds} 轮 LLM 无有效动作输出或内容重复",
                suggestion="压缩上下文至 evidence cards，强制要求输出唯一下一步动作",
            )
        return FuseDecision(level="none", fuse_type="none", reason="")

    # -- journal integration ------------------------------------------------

    def apply_to_journal(
        self,
        decision: FuseDecision,
        journal: SharedJournal,
        strategy: StrategyEngine,
    ) -> None:
        """Persist a fuse decision into the shared journal."""
        if decision.level == "none":
            return

        if decision.level in ("route", "hard"):
            journal.log_blocker(
                BlockerRecord(
                    id=f"fuse_{decision.fuse_type}_{int(time.time())}",
                    description=decision.reason,
                    route=decision.route_id or strategy._current_route or "unknown",
                    evidence=json.dumps(decision.to_dict(), ensure_ascii=False),
                    severity=decision.level,
                )
            )

        journal.write_next_actions(
            f"**熔断触发** ({decision.level}/{decision.fuse_type})\n\n"
            f"{decision.reason}\n\n"
            f"建议: {decision.suggestion}",
            role="fuse_controller",
        )

    # -- static helpers -----------------------------------------------------

    @staticmethod
    def _hash_dict(d: Dict[str, Any]) -> str:
        payload = json.dumps(d, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]
