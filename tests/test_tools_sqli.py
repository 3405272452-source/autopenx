"""Integration test for the SQLi detector against an in-process fake app."""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from config.settings import settings
from autopnex.tools.base import ToolRegistry


class _H(BaseHTTPRequestHandler):
    def log_message(self, *_a, **_k):
        return

    def do_GET(self):  # noqa: N802
        p = urlparse(self.path)
        qs = parse_qs(p.query)
        id_ = qs.get("id", ["1"])[0]
        if "'" in id_ or '"' in id_:
            body = b"You have an error in your SQL syntax near ''' at line 1"
            status = 500
        else:
            body = b"<html>item ok</html>"
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port


@pytest.fixture()
def fake():
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), _H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown(); srv.server_close()


def test_sqli_detector_finds_error_based(fake):
    tool = ToolRegistry.get("sqli_detect")
    runtime = settings.snapshot(allow_local_targets=True)
    res = tool.execute(runtime_config=runtime, url=f"{fake}/item?id=1", parameter="id", method="GET")
    assert res.success
    assert res.parsed_data["vulnerable"], res.summary
    assert "error" in res.parsed_data["signals"]
