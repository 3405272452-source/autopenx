"""End-to-end state-machine test against a synthetic in-process HTTP target.

Spins up a tiny HTTPServer that mimics a vulnerable CGI app (reflected XSS on
?q=, SQL-style error on ?id=). Runs PenTestStateMachine in --mock mode and
asserts that the pipeline completes and records at least one finding.
"""
from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from autopnex.orchestrator import LLMOrchestrator
from autopnex.report import ReportGenerator
from autopnex.state_machine import PenTestStateMachine


class _FakeApp(BaseHTTPRequestHandler):
    def log_message(self, *_a, **_k):  # silence
        return

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/":
            body = (
                "<html><head><title>FakeApp</title></head><body>"
                "<a href=\"/search?q=hello\">search</a>"
                "<form action=\"/item\" method=\"get\"><input name=\"id\" value=\"1\"></form>"
                "</body></html>"
            ).encode()
            self._ok(body, "text/html")
        elif parsed.path == "/search":
            q = qs.get("q", [""])[0]
            body = f"<html><body>results for {q}</body></html>".encode()
            self._ok(body, "text/html")
        elif parsed.path == "/item":
            id_ = qs.get("id", ["1"])[0]
            if "'" in id_ or '"' in id_:
                body = b"Warning: mysql_fetch_array(): boom\nYou have an error in your SQL syntax"
                self._ok(body, "text/html", status=500)
            else:
                body = f"<html><body>item #{id_}</body></html>".encode()
                self._ok(body, "text/html")
        elif parsed.path == "/robots.txt":
            self._ok(b"User-agent: *\nDisallow: /admin/", "text/plain")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")

    def _ok(self, body: bytes, ctype: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def fake_server():
    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), _FakeApp)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_pipeline_runs_end_to_end(tmp_path, fake_server, monkeypatch):
    # Speed up by shrinking iteration budget and wordlist.
    monkeypatch.setenv("AUTOPENX_MAX_ITER_PER_STATE", "4")
    orch = LLMOrchestrator(mock=True)
    fsm = PenTestStateMachine(target=fake_server, orchestrator=orch, max_iter_per_state=4)
    findings = fsm.run()

    assert fsm.state == "DONE"
    # At least one tool should have succeeded.
    assert any(inv.success for inv in findings.tool_invocations)
    # Report should render without errors.
    report_gen = ReportGenerator(orch.client, mode=orch.mode)
    md_path = tmp_path / "r.md"
    html_path = tmp_path / "r.html"
    report_gen.save(findings, md_path, html_path)
    assert md_path.exists() and md_path.stat().st_size > 200
    assert html_path.exists() and html_path.stat().st_size > 200


def test_progress_events_include_detailed_tool_events(fake_server):
    events = []
    orch = LLMOrchestrator(mock=True)
    fsm = PenTestStateMachine(
        target=fake_server,
        orchestrator=orch,
        max_iter_per_state=4,
        progress_callback=events.append,
    )
    findings = fsm.run()

    kinds = [event["event"] for event in events]
    assert "start" in kinds
    assert "tool_start" in kinds
    assert "tool_finish" in kinds
    assert "react_step" in kinds
    assert "done" in kinds
    assert "phase_tasks_synced" in kinds
    assert "artifact_ingested" in kinds
    assert "performance_snapshot" in kinds
    assert "exploit_planned" in kinds
    assert findings.findings
    assert any(event["event"] == "finding_update" for event in events)
