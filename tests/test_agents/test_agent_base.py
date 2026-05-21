"""AgentStatus, AgentResult, BaseAgent ABC enforcement."""
from __future__ import annotations

import pytest

from autopnex.agents.base import AgentStatus, AgentResult, BaseAgent
from autopnex.agents.blackboard import Blackboard
from autopnex.state_machine.findings import StateFindings
from config.settings import RuntimeConfig


def test_agent_status_enum_values():
    assert AgentStatus.IDLE.value == "idle"
    assert AgentStatus.RUNNING.value == "running"
    assert AgentStatus.DONE.value == "done"
    assert AgentStatus.FAILED.value == "failed"
    assert len(AgentStatus) == 4


def test_agent_result_serialization():
    result = AgentResult(
        agent_name="TestAgent",
        status=AgentStatus.DONE,
        tasks_completed=5,
        tasks_failed=1,
        duration_ms=1234,
        error=None,
        details={"key": "value"},
    )
    assert result.agent_name == "TestAgent"
    assert result.status == AgentStatus.DONE
    assert result.tasks_completed == 5
    assert result.tasks_failed == 1
    assert result.duration_ms == 1234
    assert result.error is None
    assert result.details == {"key": "value"}


def test_agent_result_with_error():
    result = AgentResult(
        agent_name="FailAgent",
        status=AgentStatus.FAILED,
        error="something went wrong",
    )
    assert result.status == AgentStatus.FAILED
    assert result.error == "something went wrong"
    assert result.tasks_completed == 0


def test_base_agent_cannot_be_instantiated_directly():
    bb = Blackboard(StateFindings(target="http://t"))
    config = RuntimeConfig()

    with pytest.raises(TypeError):
        BaseAgent(bb, config)


def test_agent_result_default_details():
    result = AgentResult(agent_name="x", status=AgentStatus.IDLE)
    assert result.details == {}
    assert result.tasks_completed == 0
    assert result.tasks_failed == 0
    assert result.duration_ms == 0
    assert result.error is None
