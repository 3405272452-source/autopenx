from __future__ import annotations

from config.settings import settings
from autopnex.orchestrator import LLMOrchestrator


class _FakeClient:
    def __init__(self, message):
        self.enabled = True
        self._message = message

    def chat(self, *_args, **_kwargs):
        return self._message


def test_orchestrator_rejects_tool_outside_phase_task_list():
    client = _FakeClient(
        {
            "content": "",
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {
                        "name": "web_scan",
                        "arguments": '{"target":"http://example.com"}',
                    },
                }
            ],
        }
    )
    orch = LLMOrchestrator(client=client, runtime_config=settings.snapshot())
    step = orch.step(
        "SCAN",
        {
            "target": "http://example.com",
            "phase_tasks": [
                {
                    "ref": "scan:crawl",
                    "phase": "SCAN",
                    "tool": "crawl",
                    "title": "Crawl pages",
                    "arguments": {"target": "http://example.com", "max_pages": 20, "max_depth": 2},
                    "status": "todo",
                }
            ],
        },
        1,
        4,
    )
    assert step.tool is None
    assert step.decision_error == "decision_rejected:not_in_phase_task_list"


def test_orchestrator_rejects_non_json_directives():
    client = _FakeClient({"content": "advance please", "tool_calls": []})
    orch = LLMOrchestrator(client=client, runtime_config=settings.snapshot())
    step = orch.step("REPORT", {"target": "http://example.com", "phase_tasks": []}, 1, 1)
    assert step.action == "stay"
    assert step.reason == "invalid_decision_format"
