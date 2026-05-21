"""CTF 核心数据模型与类型定义。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class ChallengeType(Enum):
    """CTF 题目类型枚举。

    支持五大主流 CTF 题型以及未知类型的兜底值。
    """

    WEB = "web"
    PWN = "pwn"
    CRYPTO = "crypto"
    MISC = "misc"
    REVERSE = "reverse"
    UNKNOWN = "unknown"


@dataclass
class ChallengeInput:
    """用户提交的 CTF 题目信息。

    包含解题所需的目标地址、描述、附件等输入数据。

    验证规则:
        - target 不能为空
        - flag_format 必须是合法的正则表达式
        - attachments 中的文件路径必须存在
    """

    target: str
    """URL 或目标地址，不能为空。"""

    description: str = ""
    """题目描述。"""

    challenge_type: Optional[str] = None
    """用户指定的题型（可选），如 'web'、'pwn' 等。"""

    flag_format: str = r"[A-Za-z0-9_]+\{[^}]+\}"
    """Flag 格式正则表达式，支持任意前缀如 flag{}, DASCTF{}, hgame{} 等。"""

    attachments: List[Path] = field(default_factory=list)
    """附件文件路径列表，所有路径必须存在。"""

    hints: List[str] = field(default_factory=list)
    """已知提示信息列表。"""

    platform: str = ""
    """CTF 平台名称。"""

    difficulty: str = ""
    """难度等级。"""

    def __post_init__(self) -> None:
        """验证输入数据的合法性。"""
        # target 不能为空
        if not self.target or not self.target.strip():
            raise ValueError("target 不能为空")

        # flag_format 必须是合法的正则表达式
        try:
            re.compile(self.flag_format)
        except re.error as e:
            raise ValueError(f"flag_format 不是合法的正则表达式: {e}") from e

        # attachments 中的文件路径必须存在
        for path in self.attachments:
            if not Path(path).exists():
                raise ValueError(f"附件路径不存在: {path}")


@dataclass
class ChallengeProfile:
    """题目分析后的结构化画像。

    包含题型分类、技术栈、潜在漏洞、关键线索等结构化信息，
    由题目分析器综合 LLM 语义分析和启发式规则生成。

    验证规则:
        - confidence 必须在 [0.0, 1.0] 范围内
        - challenge_type 必须是有效的 ChallengeType 枚举值
    """

    challenge_type: ChallengeType
    """题型分类，必须是有效的 ChallengeType 枚举值。"""

    sub_type: str = ""
    """子类型（如 Web-SQLi, Crypto-RSA）。"""

    tech_stack: List[str] = field(default_factory=list)
    """技术栈列表。"""

    potential_vulns: List[str] = field(default_factory=list)
    """潜在漏洞列表。"""

    key_hints: List[str] = field(default_factory=list)
    """关键线索列表。"""

    difficulty_estimate: str = "medium"
    """难度估计。"""

    similar_challenges: List[str] = field(default_factory=list)
    """相似题目 ID 列表。"""

    confidence: float = 0.0
    """分类置信度，取值范围 [0.0, 1.0]。"""

    raw_analysis: str = ""
    """LLM 原始分析文本。"""

    def __post_init__(self) -> None:
        """验证数据的合法性。"""
        # confidence 必须在 [0.0, 1.0] 范围内
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence 必须在 [0.0, 1.0] 范围内，当前值: {self.confidence}"
            )

        # challenge_type 必须是有效的 ChallengeType 枚举值
        if not isinstance(self.challenge_type, ChallengeType):
            raise TypeError(
                f"challenge_type 必须是 ChallengeType 枚举值，"
                f"当前类型: {type(self.challenge_type).__name__}"
            )


@dataclass
class FlagCandidate:
    """从输出中提取的 Flag 候选。

    包含 Flag 值、来源、置信度、编码方式和上下文信息。

    验证规则:
        - value 不能为空
        - confidence 必须在 [0.0, 1.0] 范围内
    """

    value: str
    """Flag 值，不能为空。"""

    source: str
    """来源（工具名/文件名）。"""

    confidence: float = 1.0
    """置信度，取值范围 [0.0, 1.0]，默认 1.0。"""

    encoding: str = "plaintext"
    """原始编码方式，默认 'plaintext'。"""

    context: str = ""
    """上下文片段。"""

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    """自动生成的 UTC ISO 时间戳。"""

    def __post_init__(self) -> None:
        """验证数据的合法性。"""
        # value 不能为空
        if not self.value or not self.value.strip():
            raise ValueError("value 不能为空")

        # confidence 必须在 [0.0, 1.0] 范围内
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence 必须在 [0.0, 1.0] 范围内，当前值: {self.confidence}"
            )


@dataclass
class AttackStep:
    """攻击计划中的单个步骤。

    描述一个具体的工具调用及其参数、依赖关系和优先级。

    验证规则:
        - tool 不能为空
    """

    step_id: int
    """步骤唯一标识。"""

    tool: str
    """要使用的工具名称，不能为空。"""

    arguments: Dict[str, Any] = field(default_factory=dict)
    """工具调用参数。"""

    description: str = ""
    """步骤描述。"""

    expected_outcome: str = ""
    """预期结果。"""

    depends_on: List[int] = field(default_factory=list)
    """依赖的步骤 ID 列表。"""

    priority: int = 0
    """优先级，数值越大优先级越高。"""

    def __post_init__(self) -> None:
        """验证输入数据的合法性。"""
        if not self.tool or not self.tool.strip():
            raise ValueError("tool 不能为空")


@dataclass
class AttackPlan:
    """LLM 生成的解题攻击计划。

    包含有序的攻击步骤列表、策略推理过程和备选策略。
    """

    steps: List[AttackStep] = field(default_factory=list)
    """攻击步骤列表。"""

    reasoning: str = ""
    """策略推理过程。"""

    estimated_difficulty: str = "medium"
    """预估难度。"""

    fallback_strategies: List[str] = field(default_factory=list)
    """备选策略列表。"""

    def is_empty(self) -> bool:
        """判断攻击计划是否为空（无步骤）。

        Returns:
            True 当 steps 列表为空时。
        """
        return len(self.steps) == 0

    def next_step(self, history: List[int]) -> Optional[AttackStep]:
        """获取下一个未执行的步骤。

        根据已执行步骤的 ID 历史，返回下一个尚未执行的步骤。
        按步骤在列表中的顺序返回第一个未执行的步骤。

        Args:
            history: 已执行步骤的 step_id 列表。

        Returns:
            下一个未执行的 AttackStep，若所有步骤已执行则返回 None。
        """
        executed_ids = set(history)
        for step in self.steps:
            if step.step_id not in executed_ids:
                return step
        return None


@dataclass
class CTFResult:
    """CTF 解题最终结果。

    包含解题是否成功、提取到的 Flag、题型、执行步骤数、耗时等信息。

    验证规则:
        - steps_executed >= 0
        - total_duration_ms >= 0
    """

    success: bool
    """解题是否成功。"""

    flag: Optional[str] = None
    """提取到的 Flag。"""

    challenge_type: Optional[ChallengeType] = None
    """题目类型。"""

    steps_executed: int = 0
    """已执行的步骤数，必须 >= 0。"""

    total_duration_ms: int = 0
    """总耗时（毫秒），必须 >= 0。"""

    strategy_used: str = ""
    """使用的策略描述。"""

    vulnerabilities_found: List[str] = field(default_factory=list)
    """发现的漏洞列表。"""

    error: Optional[str] = None
    """错误信息（失败时）。"""

    solve_log: List[Dict[str, Any]] = field(default_factory=list)
    """解题日志，记录每个步骤的详细信息。"""

    def __post_init__(self) -> None:
        """验证数据的合法性。"""
        if self.steps_executed < 0:
            raise ValueError(
                f"steps_executed 必须 >= 0，当前值: {self.steps_executed}"
            )
        if self.total_duration_ms < 0:
            raise ValueError(
                f"total_duration_ms 必须 >= 0，当前值: {self.total_duration_ms}"
            )


@dataclass
class StepResult:
    """单个攻击步骤的执行结果。

    记录工具调用的成功状态、输出、耗时和错误信息。

    验证规则:
        - duration_ms 必须 >= 0
    """

    success: bool
    """步骤是否执行成功。"""

    tool: str
    """使用的工具名称。"""

    arguments: Dict[str, Any] = field(default_factory=dict)
    """工具调用参数。"""

    output: str = ""
    """工具输出内容。"""

    duration_ms: int = 0
    """执行耗时（毫秒），必须 >= 0。"""

    error: Optional[str] = None
    """错误信息（失败时）。"""

    def __post_init__(self) -> None:
        """验证数据的合法性。"""
        if self.duration_ms < 0:
            raise ValueError(
                f"duration_ms 必须 >= 0，当前值: {self.duration_ms}"
            )


@dataclass
class CTFProgress:
    """实时解题进度。

    包含当前状态、步骤进度、当前动作、已找到的 Flag 和已用时间。

    验证规则:
        - step >= 0
        - total_steps >= 0
        - elapsed_ms >= 0
    """

    state: str
    """当前状态。"""

    step: int
    """当前步骤编号。"""

    total_steps: int
    """总步骤数。"""

    current_action: str = ""
    """当前动作描述。"""

    flags_found: List[str] = field(default_factory=list)
    """已找到的 Flag 列表。"""

    elapsed_ms: int = 0
    """已用时间（毫秒），必须 >= 0。"""

    def __post_init__(self) -> None:
        """验证数据的合法性。"""
        if self.step < 0:
            raise ValueError(f"step 必须 >= 0，当前值: {self.step}")
        if self.total_steps < 0:
            raise ValueError(f"total_steps 必须 >= 0，当前值: {self.total_steps}")
        if self.elapsed_ms < 0:
            raise ValueError(f"elapsed_ms 必须 >= 0，当前值: {self.elapsed_ms}")
