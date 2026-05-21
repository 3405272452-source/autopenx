"""Verify the offline MockBrain produces sensible ReAct steps per state."""
from __future__ import annotations

import json

from autopnex.orchestrator import LLMOrchestrator
from autopnex.orchestrator.mock_brain import MockBrain


def test_mock_mode_detected():
    orch = LLMOrchestrator(mock=True)
    assert orch.mode == "mock"


def test_recon_mock_cycles_through_tools():
    brain = MockBrain()
    snap = {"target": "http://example.com"}
    names = []
    for _ in range(5):
        msg = brain.decide("RECON", snap)
        if msg.get("tool_calls"):
            names.append(msg["tool_calls"][0]["function"]["name"])
        else:
            break
    assert names == ["port_scan", "tech_detect", "subdomain_find"]
    # Next call should advance
    final = brain.decide("RECON", snap)
    assert not final.get("tool_calls")
    data = json.loads(final["content"])
    assert data["action"] == "advance"


def test_vuln_detect_mock_iterates_params():
    brain = MockBrain()
    snap = {
        "parameters": [
            {"url": "http://e/q", "name": "id", "method": "GET"},
        ]
    }
    msg = brain.decide("VULN_DETECT", snap)
    assert msg["tool_calls"][0]["function"]["name"] == "sqli_detect"
