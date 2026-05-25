"""分级提示注入器。

根据 hint_schedule 配置，在指定轮次阈值时向 Agent prompt 注入分级提示。
支持 hints_enabled 开关用于基准测试中对比有提示/无提示模式的性能差异。

Requirements: 13.1, 13.2, 13.3, 13.4, 13.5
"""

from typing import Dict, List, Optional


class HintInjector:
    """分级提示注入器。

    根据 hint_schedule 中定义的轮次阈值，逐级注入提示信息。
    提示按从模糊到具体排列：
      - level-1: 漏洞类型提示
      - level-2: 利用方向提示
      - level-3: 具体 payload 格式提示

    Attributes:
        hints: 分级提示列表，索引 0 对应 level-1，索引 1 对应 level-2，索引 2 对应 level-3。
        schedule: 提示触发轮次阈值映射，如 {"1": 5, "2": 10, "3": 15}。
        enabled: 是否启用提示注入。设为 False 时用于基准测试无提示模式。
        injected_level: 当前已注入的最高提示级别（0 表示尚未注入）。
        first_hint_round: 首次提示注入发生的轮次，用于报告统计。
    """

    def __init__(
        self,
        hints: List[str],
        schedule: Dict[str, int],
        enabled: bool = True,
    ):
        self.hints = hints
        self.schedule = schedule  # {"1": 5, "2": 10, "3": 15}
        self.enabled = enabled
        self.injected_level: int = 0
        self.first_hint_round: Optional[int] = None

    def get_hint_for_round(self, current_round: int) -> Optional[str]:
        """根据当前轮次返回应注入的提示文本。

        按照从高级别到低级别的顺序检查阈值，确保在同一轮次中
        优先注入最高可用级别的提示。每个级别只注入一次。

        Args:
            current_round: 当前求解轮次编号。

        Returns:
            格式化为自然语言指令的提示文本，适合注入到 Agent 的 prompt context 中。
            如果当前轮次无需注入提示或提示已禁用，返回 None。
        """
        if not self.enabled:
            return None

        # 从高级别到低级别检查，确保优先触发最高可用级别
        for level in ["3", "2", "1"]:
            threshold = self.schedule.get(level, 999)
            if current_round >= threshold and int(level) > self.injected_level:
                self.injected_level = int(level)
                if self.first_hint_round is None:
                    self.first_hint_round = current_round
                idx = int(level) - 1
                if idx < len(self.hints):
                    return self._format_hint(self.hints[idx], int(level))
        return None

    def _format_hint(self, hint_text: str, level: int) -> str:
        """将提示文本格式化为自然语言指令，适合注入到 Agent prompt 中。

        Args:
            hint_text: 原始提示文本。
            level: 提示级别 (1-3)。

        Returns:
            格式化后的自然语言指令字符串。
        """
        level_labels = {
            1: "General guidance",
            2: "Directional hint",
            3: "Specific technique",
        }
        label = level_labels.get(level, "Hint")
        return (
            f"[{label} - Level {level}] "
            f"Consider the following when planning your next action: {hint_text}"
        )

    @property
    def hints_used(self) -> int:
        """返回已注入的提示数量，用于 Benchmark_Report 统计。"""
        return self.injected_level

    def reset(self) -> None:
        """重置注入状态，用于重新开始求解。"""
        self.injected_level = 0
        self.first_hint_round = None
