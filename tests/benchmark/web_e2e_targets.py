"""Local Web CTF targets for E2E baseline testing.

Starts a minimal Flask app with 6 vulnerable endpoints:
- LFI, SSTI, SQLi, CMDI, SSRF, JWT
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from typing import Any, Dict


def _build_app():
    try:
        from flask import Flask, request, jsonify
    except ImportError as exc:
        raise ImportError("Flask is required for E2E baseline targets") from exc

    app = Flask(__name__)

    # -------------------------------------------------------------------
    # LFI target
    # -------------------------------------------------------------------
    @app.route("/lfi")
    def lfi():
        file_path = request.args.get("file", "")
        if "flag" in file_path.lower():
            return "flag{lfi-baseline-found}"
        return f"Reading: {file_path}"

    # -------------------------------------------------------------------
    # SSTI target
    # -------------------------------------------------------------------
    @app.route("/ssti")
    def ssti():
        name = request.args.get("name", "")
        if "{{7*7}}" in name:
            return "Hello 49"
        if "cycler" in name.lower() or "os.popen" in name.lower():
            return "flag{ssti-baseline-found}"
        return f"Hello {name}"

    # -------------------------------------------------------------------
    # SQLi target
    # -------------------------------------------------------------------
    @app.route("/sqli")
    def sqli():
        item_id = request.args.get("id", "")
        if "'" in item_id and "union" not in item_id.lower():
            return "SQLSTATE[42000]: syntax error near '''"
        if "union" in item_id.lower() and "flag" in item_id.lower():
            return "flag{sqli-baseline-found}"
        return f"Item {item_id}"

    # -------------------------------------------------------------------
    # CMDI target
    # -------------------------------------------------------------------
    @app.route("/cmdi")
    def cmdi():
        cmd = request.args.get("cmd", "")
        if "cat /flag" in cmd or "cat /flag.txt" in cmd or "tac /flag" in cmd:
            return "flag{cmdi-baseline-found}"
        if ";" in cmd or "|" in cmd or "`" in cmd or "$" in cmd:
            return f"Executing: {cmd}"
        return f"Ping result: {cmd}"

    # -------------------------------------------------------------------
    # SSRF target
    # -------------------------------------------------------------------
    @app.route("/ssrf")
    def ssrf():
        url = request.args.get("url", "")
        if "127.0.0.1" in url or "0.0.0.0" in url or "file:///" in url:
            if "flag" in url.lower():
                return "flag{ssrf-baseline-found}"
        return f"Fetched: {url}"

    # -------------------------------------------------------------------
    # JWT target
    # -------------------------------------------------------------------
    @app.route("/jwt")
    def jwt():
        token = request.args.get("token", "")
        if not token:
            return jsonify({"message": "Missing token"}), 401
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        except Exception:
            return jsonify({"message": "Invalid token"}), 401
        if header.get("alg", "").lower() == "none":
            return jsonify({"message": "flag{jwt-baseline-found}"})
        return jsonify({"message": "Valid token required"}), 403

    return app


def start_e2e_server(host: str = "127.0.0.1", port: int = 0) -> Dict[str, Any]:
    """Start the E2E target server in a background thread."""
    app = _build_app()
    from werkzeug.serving import make_server

    server = make_server(host, port, app)
    actual_port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)  # Let server start
    return {
        "app": app,
        "server": server,
        "host": host,
        "port": actual_port,
        "base_url": f"http://{host}:{actual_port}",
    }


def stop_e2e_server(server_info: Dict[str, Any]) -> None:
    server_info["server"].shutdown()
