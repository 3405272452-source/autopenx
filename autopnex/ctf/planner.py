"""CTF 策略规划器 — 基于 LLM 生成解题策略和攻击路径。

利用 LLM 将题目画像转化为具体的攻击步骤序列，
支持动态重规划以避免重复失败的步骤。
"""
from __future__ import annotations

import json
import re
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from .models import AttackPlan, AttackStep, ChallengeProfile, ChallengeType, StepResult

if TYPE_CHECKING:
    from autopnex.orchestrator.llm_client import LLMClient


# ---------------------------------------------------------------------------
# 提示词模板
# ---------------------------------------------------------------------------

CTF_STRATEGY_PROMPT = """\
你是一个 CTF（Capture The Flag）竞赛解题策略专家。请根据以下题目画像生成一个详细的攻击计划。

## 题目信息
- 题型: {challenge_type}
- 子类型: {sub_type}
- 技术栈: {tech_stack}
- 潜在漏洞: {potential_vulns}
- 关键线索: {key_hints}
- 难度估计: {difficulty_estimate}

## 可用工具
{available_tools}

## 输出要求
请严格按照以下 JSON 格式输出攻击计划，不要包含其他内容：
{{
  "reasoning": "<策略推理过程>",
  "estimated_difficulty": "<easy/medium/hard>",
  "steps": [
    {{
      "step_id": 1,
      "tool": "<工具名称>",
      "arguments": {{}},
      "description": "<步骤描述>",
      "expected_outcome": "<预期结果>",
      "depends_on": [],
      "priority": 0
    }}
  ],
  "fallback_strategies": ["<备选策略1>", "<备选策略2>"]
}}

## 规则
1. 步骤必须按逻辑顺序排列（信息收集 → 漏洞检测 → 漏洞利用 → Flag 提取）
2. 每个步骤的 tool 必须是可用工具列表中的工具
3. depends_on 表示该步骤依赖哪些前置步骤完成
4. 优先使用高概率成功的攻击路径
5. 至少提供 2 个备选策略
"""

CTF_REPLAN_PROMPT = """\
你是一个 CTF 竞赛解题策略专家。之前的攻击计划部分失败，请根据执行历史重新规划。

## 题目信息
- 题型: {challenge_type}
- 子类型: {sub_type}
- 技术栈: {tech_stack}
- 潜在漏洞: {potential_vulns}
- 关键线索: {key_hints}

## 执行历史
{execution_history}

## 已失败的工具+参数组合（禁止重复使用）
{failed_combinations}

## 可用工具
{available_tools}

## 输出要求
请严格按照以下 JSON 格式输出新的攻击计划，不要包含其他内容：
{{
  "reasoning": "<新策略推理过程，说明为什么调整策略>",
  "estimated_difficulty": "<easy/medium/hard>",
  "steps": [
    {{
      "step_id": 1,
      "tool": "<工具名称>",
      "arguments": {{}},
      "description": "<步骤描述>",
      "expected_outcome": "<预期结果>",
      "depends_on": [],
      "priority": 0
    }}
  ],
  "fallback_strategies": ["<备选策略1>", "<备选策略2>"]
}}

## 规则
1. 不要重复已失败的工具+参数组合
2. 基于已成功步骤的输出调整策略
3. 尝试不同的攻击路径
4. 优先使用尚未尝试过的工具
"""


# ---------------------------------------------------------------------------
# 题型工具映射
# ---------------------------------------------------------------------------

TOOLS_BY_TYPE: Dict[ChallengeType, List[str]] = {
    ChallengeType.WEB: [
        "dir_scan",
        "sql_inject",
        "xss_detect",
        "ssti_detect",
        "lfi_detect",
        "flag_reader",
    ],
    ChallengeType.PWN: [
        "checksec",
        "rop_chain",
        "format_string",
        "remote_interact",
    ],
    ChallengeType.CRYPTO: [
        "rsa_attack",
        "classical_cipher",
        "encoding_decode",
        "script_execute",
    ],
    ChallengeType.MISC: [
        "file_analyze",
        "stego_analyze",
        "traffic_analyze",
        "archive_analyze",
    ],
    ChallengeType.REVERSE: [
        "decompile",
        "strings_extract",
        "dynamic_analyze",
        "constraint_solve",
    ],
    ChallengeType.UNKNOWN: [
        "dir_scan",
        "strings_extract",
        "file_analyze",
    ],
}


# ---------------------------------------------------------------------------
# CTFStrategyPlanner
# ---------------------------------------------------------------------------


class CTFStrategyPlanner:
    """CTF 解题策略规划器。

    基于题目分析结果，利用 LLM 生成解题策略和攻击路径，
    并支持基于执行历史的动态重规划。
    """

    def __init__(
        self,
        llm_client: "LLMClient",
        knowledge_base: Optional[Any] = None,
    ) -> None:
        """初始化策略规划器。

        Args:
            llm_client: LLM 客户端实例，用于生成攻击计划。
            knowledge_base: CTF 知识库实例（可选），用于辅助策略生成。
        """
        self.llm_client = llm_client
        self.knowledge_base = knowledge_base

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    async def plan(self, profile: ChallengeProfile) -> AttackPlan:
        """根据题目画像生成攻击计划。

        构建包含题目信息和可用工具的提示词，调用 LLM 生成攻击步骤，
        解析响应并按依赖关系排序步骤。

        Args:
            profile: 题目分析后的结构化画像。

        Returns:
            包含有序攻击步骤的 AttackPlan。
        """
        available_tools = self.get_tools_for_type(profile.challenge_type)

        prompt = CTF_STRATEGY_PROMPT.format(
            challenge_type=profile.challenge_type.value,
            sub_type=profile.sub_type or "未知",
            tech_stack=", ".join(profile.tech_stack) if profile.tech_stack else "未知",
            potential_vulns=", ".join(profile.potential_vulns) if profile.potential_vulns else "未知",
            key_hints=", ".join(profile.key_hints) if profile.key_hints else "无",
            difficulty_estimate=profile.difficulty_estimate,
            available_tools=", ".join(available_tools) if available_tools else "通用工具",
        )

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "请生成攻击计划。"},
        ]

        try:
            response = self.llm_client.chat(messages, temperature=0.3)
            content = response.get("content", "")
            plan = self._parse_plan_response(content)
        except Exception:
            # LLM 失败时返回基于题型的默认计划
            plan = self._build_default_plan(profile)

        # 按依赖关系排序步骤
        plan.steps = self._topological_sort(plan.steps)

        return plan

    async def replan(
        self,
        profile: ChallengeProfile,
        history: List[StepResult],
    ) -> AttackPlan:
        """根据已执行步骤的结果重新规划策略。

        将执行历史和失败的工具+参数组合包含在提示词中，
        要求 LLM 生成避免重复失败的新计划。

        Args:
            profile: 题目分析后的结构化画像。
            history: 已执行步骤的结果列表。

        Returns:
            新的 AttackPlan，不包含已失败的相同步骤。
        """
        available_tools = self.get_tools_for_type(profile.challenge_type)

        # 构建执行历史描述
        execution_history = self._format_history(history)

        # 提取失败的工具+参数组合
        failed_combinations = self._get_failed_combinations(history)
        failed_desc = self._format_failed_combinations(failed_combinations)

        prompt = CTF_REPLAN_PROMPT.format(
            challenge_type=profile.challenge_type.value,
            sub_type=profile.sub_type or "未知",
            tech_stack=", ".join(profile.tech_stack) if profile.tech_stack else "未知",
            potential_vulns=", ".join(profile.potential_vulns) if profile.potential_vulns else "未知",
            key_hints=", ".join(profile.key_hints) if profile.key_hints else "无",
            execution_history=execution_history,
            failed_combinations=failed_desc,
            available_tools=", ".join(available_tools) if available_tools else "通用工具",
        )

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "请生成新的攻击计划。"},
        ]

        try:
            response = self.llm_client.chat(messages, temperature=0.5)
            content = response.get("content", "")
            plan = self._parse_plan_response(content)
        except Exception:
            plan = self._build_default_plan(profile)

        # 过滤掉已失败的步骤组合
        plan.steps = self._filter_failed_steps(plan.steps, failed_combinations)

        # 按依赖关系排序步骤
        plan.steps = self._topological_sort(plan.steps)

        return plan

    def get_tools_for_type(self, challenge_type: ChallengeType) -> List[str]:
        """获取指定题型的推荐工具列表。

        Args:
            challenge_type: 题目类型枚举值。

        Returns:
            该题型对应的工具名称列表。未映射的类型返回空列表。
        """
        return list(TOOLS_BY_TYPE.get(challenge_type, []))

    def resolve_execution_order(self, plan: AttackPlan) -> List[AttackStep]:
        """基于步骤依赖关系解析执行顺序（拓扑排序）。

        对攻击计划中的步骤按 depends_on 字段进行拓扑排序，
        确保每个步骤在其依赖步骤之后执行。

        Args:
            plan: 包含攻击步骤的 AttackPlan。

        Returns:
            按依赖关系排序后的步骤列表。若存在循环依赖则按原始顺序返回。
        """
        return self._topological_sort(plan.steps)

    # ------------------------------------------------------------------
    # 步骤依赖解析与拓扑排序
    # ------------------------------------------------------------------

    def _topological_sort(self, steps: List[AttackStep]) -> List[AttackStep]:
        """基于 depends_on 字段对步骤进行拓扑排序。

        无依赖的步骤排在前面，有依赖的步骤排在其依赖步骤之后。
        若存在循环依赖，则按原始顺序返回。

        Args:
            steps: 待排序的攻击步骤列表。

        Returns:
            按依赖关系排序后的步骤列表。
        """
        if not steps:
            return []

        # 构建 step_id → step 映射
        step_map: Dict[int, AttackStep] = {s.step_id: s for s in steps}
        step_ids = set(step_map.keys())

        # 构建邻接表和入度表
        in_degree: Dict[int, int] = {sid: 0 for sid in step_ids}
        adjacency: Dict[int, List[int]] = {sid: [] for sid in step_ids}

        for step in steps:
            for dep_id in step.depends_on:
                if dep_id in step_ids:
                    adjacency[dep_id].append(step.step_id)
                    in_degree[step.step_id] += 1

        # Kahn's algorithm
        queue: deque[int] = deque()
        for sid in step_ids:
            if in_degree[sid] == 0:
                queue.append(sid)

        sorted_ids: List[int] = []
        while queue:
            # 从入度为 0 的节点中选择（按 step_id 排序保证稳定性）
            queue_list = sorted(queue)
            queue.clear()
            for sid in queue_list:
                queue.append(sid)
            current = queue.popleft()
            sorted_ids.append(current)

            for neighbor in adjacency[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # 若存在循环依赖（未能排序所有节点），按原始顺序返回
        if len(sorted_ids) != len(steps):
            return steps

        return [step_map[sid] for sid in sorted_ids]

    # ------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------

    def _parse_plan_response(self, content: str) -> AttackPlan:
        """解析 LLM 返回的攻击计划 JSON。

        支持直接 JSON、markdown 代码块包裹的 JSON、以及从文本中提取 JSON 对象。

        Args:
            content: LLM 响应内容。

        Returns:
            解析后的 AttackPlan。解析失败时返回空计划。
        """
        data = self._extract_json(content)
        if data is None:
            return AttackPlan()

        # 解析步骤
        steps: List[AttackStep] = []
        for step_data in data.get("steps", []):
            try:
                step = AttackStep(
                    step_id=int(step_data.get("step_id", len(steps) + 1)),
                    tool=str(step_data.get("tool", "")),
                    arguments=step_data.get("arguments", {}),
                    description=str(step_data.get("description", "")),
                    expected_outcome=str(step_data.get("expected_outcome", "")),
                    depends_on=step_data.get("depends_on", []),
                    priority=int(step_data.get("priority", 0)),
                )
                steps.append(step)
            except (ValueError, TypeError):
                continue

        return AttackPlan(
            steps=steps,
            reasoning=str(data.get("reasoning", "")),
            estimated_difficulty=str(data.get("estimated_difficulty", "medium")),
            fallback_strategies=data.get("fallback_strategies", []),
        )

    def _extract_json(self, content: str) -> Optional[Dict[str, Any]]:
        """从 LLM 响应中提取 JSON 对象。

        尝试顺序：直接解析 → markdown 代码块 → 文本中的 JSON 对象。

        Args:
            content: LLM 响应文本。

        Returns:
            解析后的字典，失败时返回 None。
        """
        if not content or not content.strip():
            return None

        # 尝试直接解析
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

        # 尝试从 markdown 代码块中提取
        json_match = re.search(
            r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
        )
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass

        # 尝试找到最外层的 JSON 对象
        brace_start = content.find("{")
        if brace_start != -1:
            # 找到匹配的闭合大括号
            depth = 0
            for i in range(brace_start, len(content)):
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            data = json.loads(content[brace_start:i + 1])
                            if isinstance(data, dict):
                                return data
                        except json.JSONDecodeError:
                            pass
                        break

        return None

    def _build_default_plan(self, profile: ChallengeProfile) -> AttackPlan:
        """当 LLM 不可用时，基于题型生成默认攻击计划。

        Args:
            profile: 题目画像。

        Returns:
            基于题型工具映射的默认 AttackPlan。
        """
        tools = self.get_tools_for_type(profile.challenge_type)
        steps: List[AttackStep] = []

        for i, tool in enumerate(tools):
            depends = [i] if i > 0 else []
            steps.append(AttackStep(
                step_id=i + 1,
                tool=tool,
                arguments={},
                description=f"使用 {tool} 进行分析",
                expected_outcome="获取有用信息或 Flag",
                depends_on=depends,
                priority=len(tools) - i,
            ))

        return AttackPlan(
            steps=steps,
            reasoning=f"基于 {profile.challenge_type.value} 题型的默认攻击策略",
            estimated_difficulty=profile.difficulty_estimate,
            fallback_strategies=["尝试手动分析", "切换到其他工具"],
        )

    def _format_history(self, history: List[StepResult]) -> str:
        """将执行历史格式化为可读文本。

        Args:
            history: 已执行步骤的结果列表。

        Returns:
            格式化的执行历史文本。
        """
        if not history:
            return "无执行历史"

        lines: List[str] = []
        for i, result in enumerate(history, 1):
            status = "✓ 成功" if result.success else "✗ 失败"
            line = f"{i}. [{status}] 工具: {result.tool}"
            if result.arguments:
                line += f", 参数: {json.dumps(result.arguments, ensure_ascii=False)}"
            if result.output:
                # 截断过长的输出
                output_preview = result.output[:200]
                if len(result.output) > 200:
                    output_preview += "..."
                line += f"\n   输出: {output_preview}"
            if result.error:
                line += f"\n   错误: {result.error}"
            lines.append(line)

        return "\n".join(lines)

    def _get_failed_combinations(
        self, history: List[StepResult]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """从执行历史中提取失败的工具+参数组合。

        Args:
            history: 已执行步骤的结果列表。

        Returns:
            失败的 (tool, arguments) 元组列表。
        """
        failed: List[Tuple[str, Dict[str, Any]]] = []
        for result in history:
            if not result.success:
                failed.append((result.tool, result.arguments))
        return failed

    def _format_failed_combinations(
        self, failed: List[Tuple[str, Dict[str, Any]]]
    ) -> str:
        """将失败的工具+参数组合格式化为文本。

        Args:
            failed: 失败的 (tool, arguments) 元组列表。

        Returns:
            格式化的失败组合文本。
        """
        if not failed:
            return "无"

        lines: List[str] = []
        for tool, args in failed:
            args_str = json.dumps(args, ensure_ascii=False) if args else "{}"
            lines.append(f"- {tool}({args_str})")
        return "\n".join(lines)

    def _filter_failed_steps(
        self,
        steps: List[AttackStep],
        failed_combinations: List[Tuple[str, Dict[str, Any]]],
    ) -> List[AttackStep]:
        """过滤掉与已失败组合相同的步骤。

        Args:
            steps: 待过滤的步骤列表。
            failed_combinations: 已失败的 (tool, arguments) 组合。

        Returns:
            过滤后的步骤列表。
        """
        if not failed_combinations:
            return steps

        filtered: List[AttackStep] = []
        for step in steps:
            is_failed = any(
                step.tool == tool and step.arguments == args
                for tool, args in failed_combinations
            )
            if not is_failed:
                filtered.append(step)

        return filtered
