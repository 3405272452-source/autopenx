"""Property-based tests for CTFReActAgent result structure and iteration budget.

Properties covered:

- **Property 2: Agent 结果结构完整性**
  *For any* sequence of tool execution results (success or failure), when the
  React_Agent completes its solving loop, it SHALL produce a result dictionary
  containing at minimum ``success`` (bool), and either ``flag`` (str) when
  successful or a failure reason (the ``error`` key, also serving as
  ``failure_reason``) when unsuccessful.

  **Validates: Requirements 2.3**

- **Property 3: 迭代预算强制执行**
  *For any* configured ``max_iterations`` value N, the React_Agent SHALL
  execute at most N iterations of its ReAct loop before terminating,
  regardless of tool results received.

  **Validates: Requirements 2.4**

Feature: ctf-web-agent-round7
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from hypothesis import HealthCheck, given, settings as hyp_settings
from hypothesis import strategies as st

from autopnex.ctf.react_agent import CTFReActAgent
from config.settings import settings


# ---------------------------------------------------------------------------
# Mock infrastructure
# ---------------------------------------------------------------------------


class _FakeLLMClient:
    """Stand-in for LLMClient that always reports as enabled."""

    enabled = True


def _build_agent(
    *,
    tmp_path: Path,
    max_iterations: int,
    monkeypatch: pytest.MonkeyPatch,
) -> CTFReActAgent:
    """Construct an agent with a faked LLM client and isolated workspace."""
    monkeypatch.setattr(
        "autopnex.orchestrator.llm_client.LLMClient", _FakeLLMClient
    )
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
        ctf_workspace_dir=str(tmp_path / "ctf_workspace"),
    )
    agent = CTFReActAgent(
        target="http://example.com",
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=max_iterations,
        timeout=300,
        thinking=False,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    # Stop background workers immediately - they are unrelated to the
    # property under test and may add nondeterminism.
    agent._stop_workers()
    return agent


# ---------------------------------------------------------------------------
# Hypothesis strategies for tool result sequences
# ---------------------------------------------------------------------------

# A "tool result" event is a tuple (kind, payload) describing what the agent
# observes per iteration.  The agent always sees a tool_call request from the
# (faked) LLM in every iteration; what differs is the tool_result body.
#
# Kinds:
#   - "ok"            : status_code 200, generic body, no flag
#   - "error"         : tool returned {"error": "..."}, no flag
#   - "empty"         : empty body, status_code 200
#   - "status_404"    : HTTP 404 response
#   - "status_500"    : HTTP 500 response
#   - "flag_in_body"  : body contains a valid flag (terminates loop with success)
#
# The fraction of "flag_in_body" entries is intentionally kept low so most
# generated sequences exercise the failure path (Property 2 case 2).


_TOOL_RESULT_KINDS = st.sampled_from(
    [
        "ok",
        "error",
        "empty",
        "status_404",
        "status_500",
        "flag_in_body",
    ]
)

# Bodies for "ok" responses - keep short and ASCII-clean to avoid noise in
# the flag scanner.  No braces, so no accidental flag matches.
_OK_BODIES = st.sampled_from(
    [
        "ok",
        "hello world",
        "page content",
        "no result",
        "<html><body>nothing here</body></html>",
        "200 OK",
    ]
)

_ERROR_MESSAGES = st.sampled_from(
    [
        "connection refused",
        "timeout",
        "invalid url",
        "DNS resolution failed",
        "TLS handshake error",
    ]
)


def _materialize_tool_result(kind: str, body: str, error_msg: str) -> Dict[str, Any]:
    """Translate a (kind, body, error) tuple into the dict the agent will see."""
    if kind == "ok":
        return {"status_code": 200, "url": "http://example.com", "body": body}
    if kind == "error":
        return {"error": error_msg, "status_code": 0}
    if kind == "empty":
        return {"status_code": 200, "url": "http://example.com", "body": ""}
    if kind == "status_404":
        return {"status_code": 404, "url": "http://example.com", "body": "Not Found"}
    if kind == "status_500":
        return {
            "status_code": 500,
            "url": "http://example.com",
            "body": "Internal Server Error",
        }
    if kind == "flag_in_body":
        # Use a fixed valid flag string so flag_engine recognises it with
        # high confidence (>=0.8) and the agent terminates.
        return {
            "status_code": 200,
            "url": "http://example.com",
            "body": "<html>flag{property-test-flag}</html>",
        }
    # Defensive default - should not happen given the sampled_from above.
    return {"status_code": 200, "body": ""}


# A single tool-result event.
_tool_event_strategy = st.tuples(_TOOL_RESULT_KINDS, _OK_BODIES, _ERROR_MESSAGES)


def _wire_agent(
    agent: CTFReActAgent, events: List[Tuple[str, str, str]]
) -> Dict[str, int]:
    """Patch ``_call_llm`` and ``_execute_tool`` on *agent* so each iteration
    consumes exactly one event from *events*.

    Returns a counters dict (mutated in place by the closures) so the test
    can introspect how many iterations were exercised.
    """
    counters = {"llm_calls": 0, "tool_calls": 0}
    # We always have at least one event; if Hypothesis runs out, we keep
    # returning the last event so the agent continues until it hits its
    # iteration budget on its own.
    last_event_holder: List[Tuple[str, str, str]] = [events[-1]]

    def _fake_call_llm() -> Dict[str, Any]:
        counters["llm_calls"] += 1
        # Always emit a single http_request tool_call so the agent goes
        # through the per-iteration "execute tool" branch.
        return {
            "content": "",
            "reasoning_content": "",
            "tool_calls": [
                {
                    "id": f"call_{counters['llm_calls']}",
                    "type": "function",
                    "function": {
                        "name": "http_request",
                        # Vary the URL each turn so the StrategyEngine
                        # dedup logic does not eagerly skip subsequent
                        # iterations and thereby hide the budget property.
                        "arguments": json.dumps(
                            {
                                "url": f"http://example.com/p{counters['llm_calls']}",
                                "method": "GET",
                            }
                        ),
                    },
                }
            ],
        }

    def _fake_execute_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        counters["tool_calls"] += 1
        idx = counters["tool_calls"] - 1
        if idx < len(events):
            event = events[idx]
        else:
            event = last_event_holder[0]
        kind, body, error_msg = event
        return _materialize_tool_result(kind, body, error_msg)

    agent._call_llm = _fake_call_llm  # type: ignore[assignment]
    agent._execute_tool = _fake_execute_tool  # type: ignore[assignment]
    return counters


# ---------------------------------------------------------------------------
# Property 2: Agent result structure
# ---------------------------------------------------------------------------


@hyp_settings(
    max_examples=30,
    deadline=None,  # solve() involves SharedJournal disk writes; keep relaxed
    suppress_health_check=[
        HealthCheck.function_scoped_fixture,
        HealthCheck.too_slow,
    ],
)
@given(
    events=st.lists(_tool_event_strategy, min_size=1, max_size=6),
    max_iterations=st.integers(min_value=1, max_value=5),
)
def test_agent_result_structure_is_always_well_formed(
    tmp_path_factory, monkeypatch, events, max_iterations
):
    """**Validates: Requirements 2.3**

    Property 2: For any sequence of tool execution results, the result dict
    produced by ``solve()`` must always contain a boolean ``success`` field,
    and on success a string ``flag``, on failure a failure-reason string
    available via the ``error`` key (which the codebase uses as
    ``failure_reason``).
    """
    tmp_path = tmp_path_factory.mktemp("agent_struct")
    agent = _build_agent(
        tmp_path=tmp_path, max_iterations=max_iterations, monkeypatch=monkeypatch
    )
    _wire_agent(agent, events)

    result = asyncio.run(agent.solve())

    # --- Core invariants ---
    assert isinstance(result, dict), "Result must be a dictionary"
    assert "success" in result, "Result must contain 'success' key"
    assert isinstance(result["success"], bool), "'success' must be a boolean"

    # The result must always carry a ``flag`` key (may be None on failure)
    # and an ``error`` key (None on success). This matches CTFSessionState.build_result.
    assert "flag" in result, "Result must contain 'flag' key"
    assert "error" in result, "Result must contain 'error' key (failure_reason)"

    if result["success"]:
        # Property 2 (success branch): flag must be a non-empty string.
        assert isinstance(result["flag"], str), "'flag' must be a string on success"
        assert len(result["flag"]) > 0, "'flag' must not be empty on success"
    else:
        # Property 2 (failure branch): a failure reason must be present as a
        # string. ``error`` is the canonical failure_reason field; it must not
        # be None when the run failed.
        assert isinstance(result["error"], str), (
            "Failure result must contain a string 'error' (failure_reason), "
            f"got: {type(result['error']).__name__}"
        )
        assert len(result["error"]) > 0, (
            "Failure 'error' (failure_reason) must not be empty"
        )


# ---------------------------------------------------------------------------
# Property 3: Iteration budget enforcement
# ---------------------------------------------------------------------------


@hyp_settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[
        HealthCheck.function_scoped_fixture,
        HealthCheck.too_slow,
    ],
)
@given(
    # All events are non-flag - we want to exhaust the iteration budget.
    events=st.lists(
        st.tuples(
            st.sampled_from(["ok", "error", "empty", "status_404", "status_500"]),
            _OK_BODIES,
            _ERROR_MESSAGES,
        ),
        min_size=1,
        max_size=10,
    ),
    max_iterations=st.integers(min_value=1, max_value=5),
)
def test_agent_never_exceeds_max_iterations(
    tmp_path_factory, monkeypatch, events, max_iterations
):
    """**Validates: Requirements 2.4**

    Property 3: The agent must never run more iterations than ``max_iterations``,
    regardless of tool results received. We deliberately exclude flag-bearing
    events here so the only termination condition exercised is the budget cap.
    """
    tmp_path = tmp_path_factory.mktemp("agent_budget")
    agent = _build_agent(
        tmp_path=tmp_path, max_iterations=max_iterations, monkeypatch=monkeypatch
    )
    counters = _wire_agent(agent, events)

    result = asyncio.run(agent.solve())

    # Hard upper bound: the LLM must not have been called more than
    # ``max_iterations`` times, since the agent's loop calls ``_call_llm``
    # exactly once per iteration.
    assert counters["llm_calls"] <= max_iterations, (
        f"Agent invoked LLM {counters['llm_calls']} times, "
        f"exceeding max_iterations={max_iterations}"
    )

    # The reported ``iterations`` count (number of recorded steps) must also
    # respect the budget.  Each iteration records at most one step per tool
    # call, and we issue exactly one tool call per iteration.
    assert "iterations" in result, "Result must report iteration count"
    assert result["iterations"] <= max_iterations, (
        f"Reported iterations={result['iterations']} exceeded "
        f"max_iterations={max_iterations}"
    )


# ---------------------------------------------------------------------------
# Smoke tests (concrete examples for fast diagnostics on failure)
# ---------------------------------------------------------------------------


def test_smoke_flag_event_yields_success_result(tmp_path, monkeypatch):
    """Concrete check that a flag-bearing event terminates the loop with success."""
    agent = _build_agent(tmp_path=tmp_path, max_iterations=3, monkeypatch=monkeypatch)
    _wire_agent(agent, [("flag_in_body", "ok", "")])

    result = asyncio.run(agent.solve())

    assert result["success"] is True
    assert result["flag"] == "flag{property-test-flag}"
    assert result["iterations"] <= 3


def test_smoke_only_failures_yields_failure_with_reason(tmp_path, monkeypatch):
    """Concrete check that a fully-failing run yields a non-empty ``error``."""
    agent = _build_agent(tmp_path=tmp_path, max_iterations=2, monkeypatch=monkeypatch)
    _wire_agent(agent, [("error", "ok", "boom"), ("status_500", "ok", "boom")])

    result = asyncio.run(agent.solve())

    assert result["success"] is False
    assert isinstance(result["error"], str)
    assert len(result["error"]) > 0
    assert result["iterations"] <= 2
