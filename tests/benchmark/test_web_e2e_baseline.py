"""Web CTF E2E Baseline Tests - 6 local targets: LFI SSTI SQLi CMDI SSRF JWT.

Each test starts a local vulnerable server, feeds the agent a mock LLM
that performs one http_request, and asserts that deterministic helpers
automatically retrieve the flag.

Design: The LLM is mocked (no real API key needed), but tool execution
is real — the agent makes actual HTTP requests to the Flask test server.
Deterministic helpers detect vulnerable parameters and exploit them.
"""
from __future__ import annotations

import asyncio

import pytest

from autopnex.ctf.react_agent import CTFReActAgent
from config.settings import settings

from .web_e2e_targets import start_e2e_server, stop_e2e_server


@pytest.fixture(scope="module")
def e2e_server():
    server = start_e2e_server(port=0)
    yield server
    stop_e2e_server(server)


class FakeLLMClient:
    """Minimal LLM client stub that satisfies the enabled check."""
    enabled = True

    def chat(self, **kwargs):
        # Should never be called because _call_llm is overridden
        raise RuntimeError("FakeLLMClient.chat should not be called")


def _make_agent(tmp_path, target_url, monkeypatch):
    """Create a CTFReActAgent with mocked LLM but real tool execution."""
    # Patch LLMClient at the source module so solve() imports the fake
    monkeypatch.setattr(
        "autopnex.orchestrator.llm_client.LLMClient", FakeLLMClient
    )
    runtime = settings.snapshot(
        exploit_enabled=True,
        approved_scopes=("passive", "active_scan", "exploit"),
    )
    agent = CTFReActAgent(
        target=target_url,
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=1,
        enabled_tools=["http_request"],
        runtime_config=runtime,
        knowledge_base_path=str(tmp_path / "ctf_knowledge.json"),
    )
    return agent


def _mock_llm_response(tool_name: str, arguments_json: str):
    """Build a mock LLM response that instructs the agent to call a tool."""
    return {
        "content": "",
        "reasoning_content": "Probing the target endpoint",
        "tool_calls": [
            {
                "id": "call_1",
                "function": {
                    "name": tool_name,
                    "arguments": arguments_json,
                },
            }
        ],
    }


def test_e2e_lfi(e2e_server, tmp_path, monkeypatch):
    base = e2e_server["base_url"]
    target_url = f"{base}/lfi?file=readme.txt"
    agent = _make_agent(tmp_path, target_url, monkeypatch)

    # Mock only the LLM — tool execution is real against the Flask server
    agent._call_llm = lambda: _mock_llm_response(
        "http_request",
        f'{{"url":"{target_url}","method":"GET"}}',
    )

    result = asyncio.run(agent.solve())
    assert result["success"] is True
    assert result["flag"] == "flag{lfi-baseline-found}"


def test_e2e_ssti(e2e_server, tmp_path, monkeypatch):
    base = e2e_server["base_url"]
    target_url = f"{base}/ssti?name=test"
    agent = _make_agent(tmp_path, target_url, monkeypatch)

    agent._call_llm = lambda: _mock_llm_response(
        "http_request",
        f'{{"url":"{target_url}","method":"GET"}}',
    )

    result = asyncio.run(agent.solve())
    assert result["success"] is True
    assert result["flag"] == "flag{ssti-baseline-found}"


def test_e2e_sqli(e2e_server, tmp_path, monkeypatch):
    base = e2e_server["base_url"]
    target_url = f"{base}/sqli?id=1"
    agent = _make_agent(tmp_path, target_url, monkeypatch)

    agent._call_llm = lambda: _mock_llm_response(
        "http_request",
        f'{{"url":"{target_url}","method":"GET"}}',
    )

    result = asyncio.run(agent.solve())
    assert result["success"] is True
    assert result["flag"] == "flag{sqli-baseline-found}"


def test_e2e_cmdi(e2e_server, tmp_path, monkeypatch):
    base = e2e_server["base_url"]
    target_url = f"{base}/cmdi?cmd=example.com"
    agent = _make_agent(tmp_path, target_url, monkeypatch)

    agent._call_llm = lambda: _mock_llm_response(
        "http_request",
        f'{{"url":"{target_url}","method":"GET"}}',
    )

    result = asyncio.run(agent.solve())
    assert result["success"] is True
    assert result["flag"] == "flag{cmdi-baseline-found}"


def test_e2e_ssrf(e2e_server, tmp_path, monkeypatch):
    base = e2e_server["base_url"]
    target_url = f"{base}/ssrf?url=http://example.com"
    agent = _make_agent(tmp_path, target_url, monkeypatch)

    agent._call_llm = lambda: _mock_llm_response(
        "http_request",
        f'{{"url":"{target_url}","method":"GET"}}',
    )

    result = asyncio.run(agent.solve())
    assert result["success"] is True
    assert result["flag"] == "flag{ssrf-baseline-found}"


def test_e2e_jwt(e2e_server, tmp_path, monkeypatch):
    base = e2e_server["base_url"]
    target_url = f"{base}/jwt?token=invalid"
    agent = _make_agent(tmp_path, target_url, monkeypatch)

    agent._call_llm = lambda: _mock_llm_response(
        "http_request",
        f'{{"url":"{target_url}","method":"GET"}}',
    )

    result = asyncio.run(agent.solve())
    assert result["success"] is True
    assert result["flag"] == "flag{jwt-baseline-found}"
