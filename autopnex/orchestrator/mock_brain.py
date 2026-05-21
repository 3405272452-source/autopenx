"""Deterministic rule-based brain used when no LLM API key is configured.

Mimics the decisions a well-behaved ReAct loop would make so that the demo is
fully functional offline. Each ``decide`` call returns either a tool invocation
request (matching OpenAI tool_calls shape) or a directive to advance/stay/done.
"""
from __future__ import annotations

import json
from typing import Any, Dict
from urllib.parse import urlparse


class MockBrain:
    def __init__(self) -> None:
        self._called: Dict[str, set] = {
            "RECON": set(),
            "SCAN": set(),
            "VULN_DETECT": set(),
            "EXPLOIT": set(),
        }

    def decide(self, state: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        phase_tasks = snapshot.get("phase_tasks") or []
        if phase_tasks:
            pending = [task for task in phase_tasks if task.get("status") == "todo"]
            if pending:
                task = pending[0]
                return self._tool_call(task["tool"], task.get("arguments") or {})
            return self._advance("no pending phase tasks remain")
        handler = getattr(self, f"_decide_{state.lower()}", None)
        if not handler:
            return {"content": json.dumps({"action": "advance", "reason": "no-op"}), "tool_calls": []}
        return handler(snapshot)

    # ------------------------------------------------------------------
    def _tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        call_id = f"mock-{name}-{len(self._called[name]) if name in self._called else 0}"
        return {
            "role": "assistant",
            "content": f"[mock] invoking {name}",
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }
            ],
        }

    def _advance(self, reason: str) -> Dict[str, Any]:
        return {
            "role": "assistant",
            "content": json.dumps({"action": "advance", "reason": reason}),
            "tool_calls": [],
        }

    def _stay(self, reason: str) -> Dict[str, Any]:
        return {
            "role": "assistant",
            "content": json.dumps({"action": "stay", "reason": reason}),
            "tool_calls": [],
        }

    # ------------------------------------------------------------------
    def _decide_recon(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        target = snap.get("target") or ""
        host = urlparse(target if "://" in target else f"http://{target}").hostname or target
        done = self._called["RECON"]
        if "port_scan" not in done:
            done.add("port_scan")
            return self._tool_call("port_scan", {"target": target})
        if "tech_detect" not in done:
            done.add("tech_detect")
            return self._tool_call("tech_detect", {"target": target})
        if "subdomain_find" not in done:
            done.add("subdomain_find")
            return self._tool_call("subdomain_find", {"domain": host, "limit": 30})
        return self._advance("recon tools executed once each")

    def _decide_scan(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        target = snap.get("target") or ""
        done = self._called["SCAN"]
        if "web_scan" not in done:
            done.add("web_scan")
            return self._tool_call("web_scan", {"target": target})
        if "dir_buster" not in done:
            done.add("dir_buster")
            return self._tool_call("dir_buster", {"target": target})
        if "crawl" not in done:
            done.add("crawl")
            return self._tool_call("crawl", {"target": target, "max_pages": 20, "max_depth": 2})
        return self._advance("scan tools executed once each")

    def _decide_vuln_detect(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        params = snap.get("parameters") or []
        done = self._called["VULN_DETECT"]
        # Pick the next param that hasn't been checked with each detector.
        detectors = ("sqli_detect", "xss_detect", "cmdi_detect", "ssrf_detect")
        for p in params[:8]:
            for det in detectors:
                key = f"{det}|{p['url']}|{p['name']}|{p['method']}"
                if key in done:
                    continue
                done.add(key)
                args = {"url": p["url"], "parameter": p["name"], "method": p["method"]}
                return self._tool_call(det, args)
        return self._advance("all parameters checked or none discovered")

    def _decide_exploit(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        findings = snap.get("findings") or []
        done = self._called["EXPLOIT"]
        for f in findings:
            if f.get("category") != "sqli":
                continue
            key = f"sqli_exploit|{f.get('url')}|{f.get('parameter')}"
            if key in done:
                continue
            done.add(key)
            return self._tool_call(
                "sqli_exploit",
                {"url": f["url"], "parameter": f["parameter"], "method": "GET"},
            )
        return self._advance("no more sqli findings to exploit")

    def _decide_report(self, snap: Dict[str, Any]) -> Dict[str, Any]:  # pragma: no cover
        return {
            "role": "assistant",
            "content": json.dumps({"action": "done", "reason": "ready to render report"}),
            "tool_calls": [],
        }
