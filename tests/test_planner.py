"""Unit tests for CTFStrategyPlanner with mocked LLM responses.

Tests cover:
- CTF_STRATEGY_PROMPT template string
- TOOLS_BY_TYPE mapping
- CTFStrategyPlanner.__init__()
- plan() method (LLM call + JSON parsing)
- replan() method (history exclusion + failed step filtering)
- get_tools_for_type() method
- resolve_execution_order() topological sort
- Internal helpers (_parse_plan_response, _extract_json, etc.)
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from autopnex.ctf.models import (
    AttackPlan,
    AttackStep,
    ChallengeProfile,
    ChallengeType,
    StepResult,
)
from autopnex.ctf.planner import (
    CTF_STRATEGY_PROMPT,
    CTF_REPLAN_PROMPT,
    CTFStrategyPlanner,
    TOOLS_BY_TYPE,
)


# ---------------------------------------------------------------------------
# Mock LLM Client
# ---------------------------------------------------------------------------


class MockLLMClient:
    """Mock LLM client that returns predefined responses."""

    def __init__(self, response_content: str = ""):
        self.response_content = response_content
        self.call_history: List[Dict[str, Any]] = []

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        *,
        tool_choice: str = "auto",
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> Dict[str, Any]:
        self.call_history.append({
            "messages": messages,
            "temperature": temperature,
        })
        return {
            "role": "assistant",
            "content": self.response_content,
            "tool_calls": [],
        }


class ErrorLLMClient:
    """Mock LLM client that raises exceptions."""

    def chat(self, *args, **kwargs) -> Dict[str, Any]:
        raise RuntimeError("LLM service unavailable")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_llm() -> MockLLMClient:
    """Return a mock LLM client with empty response."""
    return MockLLMClient("")


@pytest.fixture
def planner(mock_llm: MockLLMClient) -> CTFStrategyPlanner:
    """Return a CTFStrategyPlanner with mock LLM."""
    return CTFStrategyPlanner(llm_client=mock_llm, knowledge_base=None)


@pytest.fixture
def web_profile() -> ChallengeProfile:
    """Return a sample WEB challenge profile."""
    return ChallengeProfile(
        challenge_type=ChallengeType.WEB,
        sub_type="SQLi",
        tech_stack=["PHP", "MySQL"],
        potential_vulns=["SQL Injection", "LFI"],
        key_hints=["login form", "admin panel"],
        difficulty_estimate="medium",
        confidence=0.85,
    )


@pytest.fixture
def crypto_profile() -> ChallengeProfile:
    """Return a sample CRYPTO challenge profile."""
    return ChallengeProfile(
        challenge_type=ChallengeType.CRYPTO,
        sub_type="RSA",
        tech_stack=["Python", "RSA"],
        potential_vulns=["Small exponent"],
        key_hints=["e=3", "n is large"],
        difficulty_estimate="hard",
        confidence=0.9,
    )


def make_plan_response(
    steps: List[Dict[str, Any]],
    reasoning: str = "Test reasoning",
    difficulty: str = "medium",
    fallbacks: Optional[List[str]] = None,
) -> str:
    """Helper to build a valid plan JSON response."""
    return json.dumps({
        "reasoning": reasoning,
        "estimated_difficulty": difficulty,
        "steps": steps,
        "fallback_strategies": fallbacks or ["fallback1", "fallback2"],
    })


# ===========================================================================
# Tests: Prompt Templates (Task 4.7)
# ===========================================================================


class TestPromptTemplates:
    """Tests for CTF strategy prompt templates."""

    def test_strategy_prompt_contains_placeholders(self):
        """CTF_STRATEGY_PROMPT has required format placeholders."""
        assert "{challenge_type}" in CTF_STRATEGY_PROMPT
        assert "{sub_type}" in CTF_STRATEGY_PROMPT
        assert "{tech_stack}" in CTF_STRATEGY_PROMPT
        assert "{potential_vulns}" in CTF_STRATEGY_PROMPT
        assert "{key_hints}" in CTF_STRATEGY_PROMPT
        assert "{difficulty_estimate}" in CTF_STRATEGY_PROMPT
        assert "{available_tools}" in CTF_STRATEGY_PROMPT

    def test_strategy_prompt_requests_json(self):
        """CTF_STRATEGY_PROMPT requests JSON output."""
        assert "JSON" in CTF_STRATEGY_PROMPT or "json" in CTF_STRATEGY_PROMPT

    def test_replan_prompt_contains_history(self):
        """CTF_REPLAN_PROMPT has execution history placeholder."""
        assert "{execution_history}" in CTF_REPLAN_PROMPT
        assert "{failed_combinations}" in CTF_REPLAN_PROMPT

    def test_replan_prompt_contains_tools(self):
        """CTF_REPLAN_PROMPT has available tools placeholder."""
        assert "{available_tools}" in CTF_REPLAN_PROMPT


# ===========================================================================
# Tests: TOOLS_BY_TYPE Mapping (Task 4.5)
# ===========================================================================


class TestToolsByType:
    """Tests for the TOOLS_BY_TYPE mapping."""

    def test_web_tools(self):
        """WEB type has correct tools."""
        tools = TOOLS_BY_TYPE[ChallengeType.WEB]
        assert "dir_scan" in tools
        assert "sql_inject" in tools
        assert "xss_detect" in tools
        assert "ssti_detect" in tools
        assert "lfi_detect" in tools
        assert "flag_reader" in tools

    def test_pwn_tools(self):
        """PWN type has correct tools."""
        tools = TOOLS_BY_TYPE[ChallengeType.PWN]
        assert "checksec" in tools
        assert "rop_chain" in tools
        assert "format_string" in tools
        assert "remote_interact" in tools

    def test_crypto_tools(self):
        """CRYPTO type has correct tools."""
        tools = TOOLS_BY_TYPE[ChallengeType.CRYPTO]
        assert "rsa_attack" in tools
        assert "classical_cipher" in tools
        assert "encoding_decode" in tools
        assert "script_execute" in tools

    def test_misc_tools(self):
        """MISC type has correct tools."""
        tools = TOOLS_BY_TYPE[ChallengeType.MISC]
        assert "file_analyze" in tools
        assert "stego_analyze" in tools
        assert "traffic_analyze" in tools
        assert "archive_analyze" in tools

    def test_reverse_tools(self):
        """REVERSE type has correct tools."""
        tools = TOOLS_BY_TYPE[ChallengeType.REVERSE]
        assert "decompile" in tools
        assert "strings_extract" in tools
        assert "dynamic_analyze" in tools
        assert "constraint_solve" in tools

    def test_unknown_tools(self):
        """UNKNOWN type has fallback tools."""
        tools = TOOLS_BY_TYPE[ChallengeType.UNKNOWN]
        assert "dir_scan" in tools
        assert "strings_extract" in tools
        assert "file_analyze" in tools

    def test_all_types_covered(self):
        """All ChallengeType values have tool mappings."""
        for ct in ChallengeType:
            assert ct in TOOLS_BY_TYPE


# ===========================================================================
# Tests: CTFStrategyPlanner.__init__() (Task 4.2)
# ===========================================================================


class TestPlannerInit:
    """Tests for CTFStrategyPlanner initialization."""

    def test_init_with_llm_client(self):
        """Planner stores llm_client reference."""
        llm = MockLLMClient()
        planner = CTFStrategyPlanner(llm_client=llm)
        assert planner.llm_client is llm

    def test_init_with_knowledge_base(self):
        """Planner stores knowledge_base reference."""
        llm = MockLLMClient()
        kb = object()
        planner = CTFStrategyPlanner(llm_client=llm, knowledge_base=kb)
        assert planner.knowledge_base is kb

    def test_init_knowledge_base_default_none(self):
        """Knowledge base defaults to None."""
        llm = MockLLMClient()
        planner = CTFStrategyPlanner(llm_client=llm)
        assert planner.knowledge_base is None


# ===========================================================================
# Tests: get_tools_for_type() (Task 4.5)
# ===========================================================================


class TestGetToolsForType:
    """Tests for get_tools_for_type method."""

    def test_web_type(self, planner: CTFStrategyPlanner):
        """Returns WEB tools for WEB type."""
        tools = planner.get_tools_for_type(ChallengeType.WEB)
        assert tools == TOOLS_BY_TYPE[ChallengeType.WEB]

    def test_pwn_type(self, planner: CTFStrategyPlanner):
        """Returns PWN tools for PWN type."""
        tools = planner.get_tools_for_type(ChallengeType.PWN)
        assert tools == TOOLS_BY_TYPE[ChallengeType.PWN]

    def test_returns_copy(self, planner: CTFStrategyPlanner):
        """Returns a copy, not the original list."""
        tools = planner.get_tools_for_type(ChallengeType.WEB)
        tools.append("extra_tool")
        assert "extra_tool" not in TOOLS_BY_TYPE[ChallengeType.WEB]


# ===========================================================================
# Tests: plan() method (Task 4.3)
# ===========================================================================


class TestPlan:
    """Tests for the plan() method."""

    @pytest.mark.asyncio
    async def test_plan_calls_llm(self, web_profile: ChallengeProfile):
        """plan() calls LLM with correct prompt."""
        response = make_plan_response([
            {
                "step_id": 1,
                "tool": "dir_scan",
                "arguments": {"target": "http://example.com"},
                "description": "Scan directories",
                "expected_outcome": "Find hidden paths",
                "depends_on": [],
                "priority": 3,
            },
        ])
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        plan = await planner.plan(web_profile)

        assert len(llm.call_history) == 1
        assert llm.call_history[0]["temperature"] == 0.3

    @pytest.mark.asyncio
    async def test_plan_parses_steps(self, web_profile: ChallengeProfile):
        """plan() correctly parses steps from LLM response."""
        response = make_plan_response([
            {
                "step_id": 1,
                "tool": "dir_scan",
                "arguments": {"target": "http://example.com"},
                "description": "Scan directories",
                "expected_outcome": "Find hidden paths",
                "depends_on": [],
                "priority": 3,
            },
            {
                "step_id": 2,
                "tool": "sql_inject",
                "arguments": {"url": "http://example.com/login"},
                "description": "Test SQL injection",
                "expected_outcome": "Extract data",
                "depends_on": [1],
                "priority": 2,
            },
        ])
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        plan = await planner.plan(web_profile)

        assert len(plan.steps) == 2
        assert plan.steps[0].tool == "dir_scan"
        assert plan.steps[1].tool == "sql_inject"
        assert plan.steps[1].depends_on == [1]

    @pytest.mark.asyncio
    async def test_plan_parses_reasoning(self, web_profile: ChallengeProfile):
        """plan() parses reasoning and metadata."""
        response = make_plan_response(
            steps=[{"step_id": 1, "tool": "dir_scan", "arguments": {}, "description": "", "expected_outcome": "", "depends_on": [], "priority": 0}],
            reasoning="Start with directory scanning",
            difficulty="easy",
            fallbacks=["Try XSS", "Try SSTI"],
        )
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        plan = await planner.plan(web_profile)

        assert plan.reasoning == "Start with directory scanning"
        assert plan.estimated_difficulty == "easy"
        assert "Try XSS" in plan.fallback_strategies

    @pytest.mark.asyncio
    async def test_plan_llm_failure_returns_default(self, web_profile: ChallengeProfile):
        """plan() returns default plan when LLM fails."""
        planner = CTFStrategyPlanner(llm_client=ErrorLLMClient())

        plan = await planner.plan(web_profile)

        assert not plan.is_empty()
        # Default plan uses tools from the type mapping
        tool_names = [s.tool for s in plan.steps]
        for tool in tool_names:
            assert tool in TOOLS_BY_TYPE[ChallengeType.WEB]

    @pytest.mark.asyncio
    async def test_plan_invalid_json_returns_empty(self, web_profile: ChallengeProfile):
        """plan() returns empty plan when LLM returns unparseable JSON."""
        llm = MockLLMClient("This is not valid JSON at all")
        planner = CTFStrategyPlanner(llm_client=llm)

        plan = await planner.plan(web_profile)

        # When LLM responds but JSON is invalid, plan is empty (no exception raised)
        assert plan.is_empty()

    @pytest.mark.asyncio
    async def test_plan_json_in_markdown_block(self, web_profile: ChallengeProfile):
        """plan() parses JSON wrapped in markdown code block."""
        inner_json = json.dumps({
            "reasoning": "markdown wrapped",
            "estimated_difficulty": "medium",
            "steps": [{"step_id": 1, "tool": "dir_scan", "arguments": {}, "description": "scan", "expected_outcome": "paths", "depends_on": [], "priority": 1}],
            "fallback_strategies": [],
        })
        response = f"```json\n{inner_json}\n```"
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        plan = await planner.plan(web_profile)

        assert plan.reasoning == "markdown wrapped"
        assert len(plan.steps) == 1

    @pytest.mark.asyncio
    async def test_plan_prompt_includes_profile_info(self, web_profile: ChallengeProfile):
        """plan() includes profile info in the prompt."""
        response = make_plan_response([{"step_id": 1, "tool": "dir_scan", "arguments": {}, "description": "", "expected_outcome": "", "depends_on": [], "priority": 0}])
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        await planner.plan(web_profile)

        prompt_content = llm.call_history[0]["messages"][0]["content"]
        assert "web" in prompt_content
        assert "PHP" in prompt_content
        assert "SQL Injection" in prompt_content


# ===========================================================================
# Tests: replan() method (Task 4.4)
# ===========================================================================


class TestReplan:
    """Tests for the replan() method."""

    @pytest.mark.asyncio
    async def test_replan_calls_llm_with_history(self, web_profile: ChallengeProfile):
        """replan() includes execution history in prompt."""
        response = make_plan_response([
            {"step_id": 1, "tool": "xss_detect", "arguments": {}, "description": "Try XSS", "expected_outcome": "XSS found", "depends_on": [], "priority": 1},
        ])
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        history = [
            StepResult(success=False, tool="sql_inject", arguments={"url": "http://x.com"}, output="", error="No vuln found"),
            StepResult(success=True, tool="dir_scan", arguments={}, output="/admin found"),
        ]

        plan = await planner.replan(web_profile, history)

        assert len(llm.call_history) == 1
        prompt_content = llm.call_history[0]["messages"][0]["content"]
        assert "sql_inject" in prompt_content

    @pytest.mark.asyncio
    async def test_replan_filters_failed_steps(self, web_profile: ChallengeProfile):
        """replan() filters out steps matching failed combinations."""
        response = make_plan_response([
            {"step_id": 1, "tool": "sql_inject", "arguments": {"url": "http://x.com"}, "description": "SQLi", "expected_outcome": "", "depends_on": [], "priority": 1},
            {"step_id": 2, "tool": "xss_detect", "arguments": {"url": "http://x.com"}, "description": "XSS", "expected_outcome": "", "depends_on": [], "priority": 1},
        ])
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        history = [
            StepResult(success=False, tool="sql_inject", arguments={"url": "http://x.com"}, output="", error="Failed"),
        ]

        plan = await planner.replan(web_profile, history)

        # sql_inject with same args should be filtered
        tool_names = [s.tool for s in plan.steps]
        # The exact same tool+args combo should be removed
        for step in plan.steps:
            if step.tool == "sql_inject":
                assert step.arguments != {"url": "http://x.com"}

    @pytest.mark.asyncio
    async def test_replan_uses_higher_temperature(self, web_profile: ChallengeProfile):
        """replan() uses higher temperature for more creative strategies."""
        response = make_plan_response([{"step_id": 1, "tool": "xss_detect", "arguments": {}, "description": "", "expected_outcome": "", "depends_on": [], "priority": 0}])
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        history = [StepResult(success=False, tool="dir_scan", arguments={}, output="")]

        await planner.replan(web_profile, history)

        assert llm.call_history[0]["temperature"] == 0.5

    @pytest.mark.asyncio
    async def test_replan_llm_failure_returns_default(self, web_profile: ChallengeProfile):
        """replan() returns default plan when LLM fails."""
        planner = CTFStrategyPlanner(llm_client=ErrorLLMClient())

        history = [StepResult(success=False, tool="dir_scan", arguments={}, output="")]

        plan = await planner.replan(web_profile, history)

        assert not plan.is_empty()

    @pytest.mark.asyncio
    async def test_replan_empty_history(self, web_profile: ChallengeProfile):
        """replan() works with empty history."""
        response = make_plan_response([{"step_id": 1, "tool": "dir_scan", "arguments": {}, "description": "", "expected_outcome": "", "depends_on": [], "priority": 0}])
        llm = MockLLMClient(response)
        planner = CTFStrategyPlanner(llm_client=llm)

        plan = await planner.replan(web_profile, [])

        assert not plan.is_empty()


# ===========================================================================
# Tests: resolve_execution_order() (Task 4.6)
# ===========================================================================


class TestResolveExecutionOrder:
    """Tests for topological sort of attack steps."""

    def test_no_dependencies(self, planner: CTFStrategyPlanner):
        """Steps without dependencies maintain order."""
        plan = AttackPlan(steps=[
            AttackStep(step_id=1, tool="dir_scan"),
            AttackStep(step_id=2, tool="sql_inject"),
            AttackStep(step_id=3, tool="xss_detect"),
        ])

        ordered = planner.resolve_execution_order(plan)

        assert len(ordered) == 3
        # All steps present
        ids = [s.step_id for s in ordered]
        assert set(ids) == {1, 2, 3}

    def test_linear_dependencies(self, planner: CTFStrategyPlanner):
        """Linear chain: 1 -> 2 -> 3."""
        plan = AttackPlan(steps=[
            AttackStep(step_id=3, tool="flag_reader", depends_on=[2]),
            AttackStep(step_id=1, tool="dir_scan", depends_on=[]),
            AttackStep(step_id=2, tool="sql_inject", depends_on=[1]),
        ])

        ordered = planner.resolve_execution_order(plan)

        ids = [s.step_id for s in ordered]
        assert ids.index(1) < ids.index(2)
        assert ids.index(2) < ids.index(3)

    def test_diamond_dependencies(self, planner: CTFStrategyPlanner):
        """Diamond: 1 -> 2, 1 -> 3, 2 -> 4, 3 -> 4."""
        plan = AttackPlan(steps=[
            AttackStep(step_id=1, tool="dir_scan", depends_on=[]),
            AttackStep(step_id=2, tool="sql_inject", depends_on=[1]),
            AttackStep(step_id=3, tool="xss_detect", depends_on=[1]),
            AttackStep(step_id=4, tool="flag_reader", depends_on=[2, 3]),
        ])

        ordered = planner.resolve_execution_order(plan)

        ids = [s.step_id for s in ordered]
        assert ids.index(1) < ids.index(2)
        assert ids.index(1) < ids.index(3)
        assert ids.index(2) < ids.index(4)
        assert ids.index(3) < ids.index(4)

    def test_cyclic_dependencies_returns_original(self, planner: CTFStrategyPlanner):
        """Cyclic dependencies return original order."""
        plan = AttackPlan(steps=[
            AttackStep(step_id=1, tool="dir_scan", depends_on=[2]),
            AttackStep(step_id=2, tool="sql_inject", depends_on=[1]),
        ])

        ordered = planner.resolve_execution_order(plan)

        # Should return original order since cycle detected
        assert len(ordered) == 2

    def test_empty_plan(self, planner: CTFStrategyPlanner):
        """Empty plan returns empty list."""
        plan = AttackPlan(steps=[])

        ordered = planner.resolve_execution_order(plan)

        assert ordered == []

    def test_single_step(self, planner: CTFStrategyPlanner):
        """Single step returns that step."""
        plan = AttackPlan(steps=[
            AttackStep(step_id=1, tool="dir_scan"),
        ])

        ordered = planner.resolve_execution_order(plan)

        assert len(ordered) == 1
        assert ordered[0].step_id == 1

    def test_dependency_on_nonexistent_step(self, planner: CTFStrategyPlanner):
        """Dependency on non-existent step_id is ignored."""
        plan = AttackPlan(steps=[
            AttackStep(step_id=1, tool="dir_scan", depends_on=[99]),
            AttackStep(step_id=2, tool="sql_inject", depends_on=[1]),
        ])

        ordered = planner.resolve_execution_order(plan)

        ids = [s.step_id for s in ordered]
        assert ids.index(1) < ids.index(2)


# ===========================================================================
# Tests: Internal helpers
# ===========================================================================


class TestInternalHelpers:
    """Tests for internal helper methods."""

    def test_extract_json_direct(self, planner: CTFStrategyPlanner):
        """_extract_json parses direct JSON."""
        data = planner._extract_json('{"key": "value"}')
        assert data == {"key": "value"}

    def test_extract_json_markdown_block(self, planner: CTFStrategyPlanner):
        """_extract_json parses markdown code block."""
        content = '```json\n{"key": "value"}\n```'
        data = planner._extract_json(content)
        assert data == {"key": "value"}

    def test_extract_json_embedded(self, planner: CTFStrategyPlanner):
        """_extract_json finds JSON in surrounding text."""
        content = 'Here is the plan: {"key": "value"} end.'
        data = planner._extract_json(content)
        assert data == {"key": "value"}

    def test_extract_json_empty(self, planner: CTFStrategyPlanner):
        """_extract_json returns None for empty input."""
        assert planner._extract_json("") is None
        assert planner._extract_json("   ") is None

    def test_extract_json_invalid(self, planner: CTFStrategyPlanner):
        """_extract_json returns None for invalid JSON."""
        assert planner._extract_json("not json at all") is None

    def test_parse_plan_response_valid(self, planner: CTFStrategyPlanner):
        """_parse_plan_response parses valid plan JSON."""
        content = make_plan_response([
            {"step_id": 1, "tool": "dir_scan", "arguments": {}, "description": "scan", "expected_outcome": "paths", "depends_on": [], "priority": 1},
        ])
        plan = planner._parse_plan_response(content)
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "dir_scan"

    def test_parse_plan_response_empty(self, planner: CTFStrategyPlanner):
        """_parse_plan_response returns empty plan for empty input."""
        plan = planner._parse_plan_response("")
        assert plan.is_empty()

    def test_parse_plan_response_invalid_step_skipped(self, planner: CTFStrategyPlanner):
        """_parse_plan_response skips steps with invalid tool (empty)."""
        content = json.dumps({
            "reasoning": "test",
            "estimated_difficulty": "medium",
            "steps": [
                {"step_id": 1, "tool": "", "arguments": {}, "description": "", "expected_outcome": "", "depends_on": [], "priority": 0},
                {"step_id": 2, "tool": "dir_scan", "arguments": {}, "description": "", "expected_outcome": "", "depends_on": [], "priority": 0},
            ],
            "fallback_strategies": [],
        })
        plan = planner._parse_plan_response(content)
        # Empty tool raises ValueError in AttackStep, so it's skipped
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "dir_scan"

    def test_format_history_empty(self, planner: CTFStrategyPlanner):
        """_format_history returns placeholder for empty history."""
        result = planner._format_history([])
        assert result == "无执行历史"

    def test_format_history_with_results(self, planner: CTFStrategyPlanner):
        """_format_history formats results correctly."""
        history = [
            StepResult(success=True, tool="dir_scan", arguments={}, output="/admin found"),
            StepResult(success=False, tool="sql_inject", arguments={"url": "http://x.com"}, output="", error="No vuln"),
        ]
        result = planner._format_history(history)
        assert "dir_scan" in result
        assert "sql_inject" in result
        assert "成功" in result
        assert "失败" in result

    def test_get_failed_combinations(self, planner: CTFStrategyPlanner):
        """_get_failed_combinations extracts only failed entries."""
        history = [
            StepResult(success=True, tool="dir_scan", arguments={}),
            StepResult(success=False, tool="sql_inject", arguments={"url": "http://x.com"}),
            StepResult(success=False, tool="xss_detect", arguments={"param": "q"}),
        ]
        failed = planner._get_failed_combinations(history)
        assert len(failed) == 2
        assert ("sql_inject", {"url": "http://x.com"}) in failed
        assert ("xss_detect", {"param": "q"}) in failed

    def test_filter_failed_steps(self, planner: CTFStrategyPlanner):
        """_filter_failed_steps removes matching tool+args combos."""
        steps = [
            AttackStep(step_id=1, tool="sql_inject", arguments={"url": "http://x.com"}),
            AttackStep(step_id=2, tool="xss_detect", arguments={"param": "q"}),
            AttackStep(step_id=3, tool="sql_inject", arguments={"url": "http://y.com"}),
        ]
        failed = [("sql_inject", {"url": "http://x.com"})]

        filtered = planner._filter_failed_steps(steps, failed)

        assert len(filtered) == 2
        assert all(s.step_id != 1 for s in filtered)

    def test_filter_failed_steps_empty_failed(self, planner: CTFStrategyPlanner):
        """_filter_failed_steps returns all steps when no failures."""
        steps = [
            AttackStep(step_id=1, tool="dir_scan"),
            AttackStep(step_id=2, tool="sql_inject"),
        ]
        filtered = planner._filter_failed_steps(steps, [])
        assert len(filtered) == 2

    def test_build_default_plan(self, planner: CTFStrategyPlanner):
        """_build_default_plan creates plan from type tools."""
        profile = ChallengeProfile(
            challenge_type=ChallengeType.CRYPTO,
            confidence=0.8,
        )
        plan = planner._build_default_plan(profile)

        assert not plan.is_empty()
        tool_names = [s.tool for s in plan.steps]
        for tool in tool_names:
            assert tool in TOOLS_BY_TYPE[ChallengeType.CRYPTO]
