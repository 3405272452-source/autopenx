"""多尝试机制 — 支持多次独立尝试解题，每次使用不同温度参数。

通过多次独立尝试（每次重置环境、调整 LLM 温度）提升解题成功率。
适用于需要探索性思维的 CTF 题目，高温度参数鼓励 LLM 产生更有创意的解题策略。
支持退避延迟（backoff）机制，在连续失败时逐步增加尝试间隔。
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

from .models import CTFResult

if TYPE_CHECKING:
    from .controller import CTFModeController

logger = logging.getLogger(__name__)


@dataclass
class AttemptConfig:
    """多尝试机制配置。

    控制最大尝试次数、每次尝试的 LLM 温度参数、环境重置策略和退避因子。

    验证规则:
        - max_attempts 必须 >= 1
        - temperature_schedule 不能为空
        - temperature_schedule 中每个值必须在 [0.0, 2.0] 范围内
        - backoff_factor 必须 >= 0.0
    """

    max_attempts: int = 10
    """最大尝试次数，默认 10。"""

    temperature_schedule: List[float] = field(
        default_factory=lambda: [0.3, 0.5, 0.7, 0.9, 1.0]
    )
    """每次尝试对应的 LLM 温度参数列表。

    第 i 次尝试使用 temperature_schedule[i % len(temperature_schedule)]。
    温度越高，LLM 响应越具探索性和创意性。
    """

    reset_env_between_attempts: bool = True
    """是否在每次尝试之间重置环境（清除控制器内部状态），默认 True。"""

    backoff_factor: float = 1.5
    """退避因子 — 连续失败时尝试间延迟的乘数，默认 1.5。

    第 i 次失败后的延迟 = backoff_factor^i 秒（i 从 0 开始）。
    设为 0 则不进行延迟。
    """

    def __post_init__(self) -> None:
        """验证配置的合法性。"""
        if self.max_attempts < 1:
            raise ValueError(
                f"max_attempts 必须 >= 1，当前值: {self.max_attempts}"
            )
        if not self.temperature_schedule:
            raise ValueError("temperature_schedule 不能为空")
        for i, temp in enumerate(self.temperature_schedule):
            if not (0.0 <= temp <= 2.0):
                raise ValueError(
                    f"temperature_schedule[{i}] 必须在 [0.0, 2.0] 范围内，"
                    f"当前值: {temp}"
                )
        if self.backoff_factor < 0.0:
            raise ValueError(
                f"backoff_factor 必须 >= 0.0，当前值: {self.backoff_factor}"
            )


class MultiAttemptSolver:
    """多尝试解题器。

    通过多次独立尝试解题，每次尝试使用不同的 LLM 温度参数，
    并在每次尝试之间重置环境（可选），以提升解题成功率。

    使用方式::

        from autopnex.ctf.react_agent import CTFReActAgent
        from autopnex.ctf.multi_attempt import AttemptConfig, MultiAttemptSolver

        agent = CTFReActAgent(target="http://example.com")
        config = AttemptConfig(max_attempts=5)
        solver = MultiAttemptSolver(config=config, controller=agent)
        result = await solver.solve_with_retries()
    """

    def __init__(
        self,
        config: AttemptConfig,
        controller: "CTFModeController",
    ) -> None:
        """初始化多尝试解题器。

        Args:
            config: 多尝试配置，控制尝试次数、温度调度、退避等。
            controller: CTFModeController 实例，用于执行解题。
        """
        self.config = config
        self._controller = controller

        # 尝试结果记录
        self._attempt_results: List[CTFResult] = []

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    async def solve_with_retries(self) -> CTFResult:
        """执行多次独立尝试，返回第一个成功结果或最后一次失败结果。

        按顺序执行最多 max_attempts 次独立尝试：
        - 每次尝试前重置环境（若 reset_env_between_attempts=True）
        - 每次尝试使用对应的温度参数
        - 找到成功结果后立即返回
        - 连续失败时按 backoff_factor 进行退避延迟
        - 所有尝试均失败时返回最后一次的失败结果

        Returns:
            第一个成功的 CTFResult，或所有尝试中最后一次的失败结果。
        """
        self._attempt_results = []
        last_result: Optional[CTFResult] = None

        for attempt_idx in range(self.config.max_attempts):
            temperature = self._get_temperature(attempt_idx)
            logger.info(
                "开始第 %d/%d 次尝试，温度=%.2f",
                attempt_idx + 1,
                self.config.max_attempts,
                temperature,
            )

            # 重置环境（第一次尝试也会重置以确保干净状态）
            if self.config.reset_env_between_attempts:
                self._reset_environment()

            # 执行本次尝试
            try:
                result = await self._controller.solve()
            except Exception as exc:  # noqa: BLE001
                logger.error("第 %d 次尝试发生异常: %s", attempt_idx + 1, exc)
                result = CTFResult(
                    success=False,
                    error=str(exc),
                    steps_executed=0,
                    total_duration_ms=0,
                )

            self._attempt_results.append(result)
            last_result = result

            if result.success:
                logger.info(
                    "第 %d 次尝试成功，Flag: %s",
                    attempt_idx + 1,
                    result.flag,
                )
                return result

            logger.info(
                "第 %d 次尝试失败，错误: %s",
                attempt_idx + 1,
                result.error,
            )

            # 退避延迟（最后一次失败后不需要延迟）
            if attempt_idx < self.config.max_attempts - 1 and self.config.backoff_factor > 0:
                delay = self.config.backoff_factor ** attempt_idx
                logger.debug("退避延迟 %.2f 秒", delay)
                await asyncio.sleep(delay)

        # 所有尝试均失败，返回最后一次结果
        assert last_result is not None
        return last_result

    def _reset_environment(self) -> None:
        """重置控制器内部状态，为下一次尝试提供干净的环境。

        清除控制器的以下内部状态：
        - _current_state: 重置为 "INIT"
        - _steps_executed: 重置为 0
        - _start_time: 重置为 None
        - _total_steps: 重置为 0
        - _current_action: 重置为空字符串
        - _flags_found: 清空列表
        """
        logger.debug("重置控制器环境状态")
        controller = self._controller

        # 重置进度状态
        controller._current_state = "INIT"
        controller._steps_executed = 0
        controller._start_time = None
        controller._total_steps = 0
        controller._current_action = ""
        controller._flags_found = []

    def _get_temperature(self, attempt: int) -> float:
        """根据尝试索引返回对应的温度参数。

        使用循环索引访问 temperature_schedule，支持尝试次数超过调度列表长度的情况。

        Args:
            attempt: 尝试索引（从 0 开始）。

        Returns:
            对应的温度参数（float）。

        Examples:
            >>> config = AttemptConfig(temperature_schedule=[0.3, 0.5, 0.7, 0.9, 1.0])
            >>> solver = MultiAttemptSolver(config, controller)
            >>> solver._get_temperature(0)  # 0.3
            >>> solver._get_temperature(4)  # 1.0
            >>> solver._get_temperature(5)  # 0.3 (cycles)
        """
        schedule = self.config.temperature_schedule
        return schedule[attempt % len(schedule)]

    @property
    def attempt_results(self) -> List[CTFResult]:
        """返回所有已完成尝试的结果列表（只读副本）。"""
        return list(self._attempt_results)
