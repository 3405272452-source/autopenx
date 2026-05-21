"""Benchmark challenge definitions — 30 web CTF challenges.

Each challenge is a self-contained Python class that:
  - Starts a local HTTP server on a random port
  - Exposes the vulnerable endpoint(s)
  - Has a fixed, known flag
  - Can be started/stopped independently

Categories (per roadmap 9.2):
  source_leak(3), LFI(3), SSTI(3), SQLi(4), CMDI(3), SSRF(3),
  JWT(3), Upload(3), PHP POP(2), IDOR(2), XSS(2), GraphQL/WebSocket(2)
"""

from __future__ import annotations

import json
import os
import random
import socket
import threading
from abc import ABC, abstractmethod
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# Port management
# ---------------------------------------------------------------------------

def _find_free_port() -> int:
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Base challenge handler and target
# ---------------------------------------------------------------------------

class ChallengeHandler(BaseHTTPRequestHandler):
    """Base HTTP handler for benchmark challenges."""
    challenge: "ChallengeTarget" = None  # Set by the server

    def log_message(self, format, *args):  # noqa: A002
        pass  # Suppress HTTP server logs during benchmark

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _parse_query(self) -> Dict[str, List[str]]:
        parsed = urlparse(self.path)
        return parse_qs(parsed.query)

    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "Benchmark-Challenge/1.0")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        self.challenge.handle_GET(self)

    def do_POST(self):
        self.challenge.handle_POST(self)


class ChallengeTarget(ABC):
    """Abstract base for a benchmark challenge target.

    Subclasses override:
      - flag: the known flag value
      - flag_format: regex pattern
      - category: route category (lfi, sqli, etc.)
      - handle_GET / handle_POST: HTTP handlers
    """

    flag: str = "flag{benchmark_test_placeholder}"
    flag_format: str = r"flag\{[^}]+\}"
    category: str = "unknown"
    name: str = "benchmark_challenge"

    def __init__(self):
        self.port = _find_free_port()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> str:
        """Start the challenge server. Returns the target URL."""
        handler = type(
            f"{self.__class__.__name__}Handler",
            (ChallengeHandler,),
            {"challenge": self},
        )
        self._server = HTTPServer(("127.0.0.1", self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        """Stop the challenge server."""
        if self._server:
            self._server.shutdown()
            self._server = None

    def cleanup(self):
        """Clean up any files created by this challenge. Override in subclasses."""
        pass

    # ------------------------------------------------------------------
    # HTTP handlers — override in subclasses
    # ------------------------------------------------------------------

    def handle_GET(self, handler: ChallengeHandler):
        handler._send(404, "Not Found")

    def handle_POST(self, handler: ChallengeHandler):
        handler._send(404, "Not Found")


# ============================================================================
# SOURCE_LEAK challenges (3)
# ============================================================================

class SourceLeakGitHead(ChallengeTarget):
    """Challenge: .git/HEAD exposed, flag in source code accessible via .git objects."""
    category = "source_leak"
    name = "source_leak_git_head"
    flag = "flag{g1t_l34k_m4st3r_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path
        if path == "/.git/HEAD":
            handler._send(200, "ref: refs/heads/main\n", "text/plain")
        elif path == "/.git/config":
            handler._send(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n", "text/plain")
        elif path == "/index.php.bak":
            handler._send(200, f"<?php\n// Source code backup\n// Flag: {self.flag}\n$app = new App();\n$app->run();\n?>", "text/plain")
        elif path == "/.env":
            handler._send(200, f"APP_ENV=production\nAPP_KEY=base64:abc123\nFLAG={self.flag}\n", "text/plain")
        elif path == "/":
            handler._send(200, """
            <html><head><title>PHP App</title></head>
            <body><h1>Welcome</h1><p>This is a simple PHP application.</p></body>
            </html>
            """)
        else:
            handler._send(404, "Not Found")


class SourceLeakBackupZip(ChallengeTarget):
    """Challenge: /www.zip backup file downloadable."""
    category = "source_leak"
    name = "source_leak_backup_zip"
    flag = "flag{b4ckup_z1p_l34k_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path
        if path == "/www.zip":
            # Return a minimal valid ZIP with a readme containing the flag hint
            import zipfile
            import io
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as zf:
                zf.writestr("index.php", f"<?php\n// config file\n$flag = '{self.flag}';\n?>")
                zf.writestr("config.php", "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n?>")
            handler.send_response(200)
            handler.send_header("Content-Type", "application/zip")
            handler.end_headers()
            handler.wfile.write(buf.getvalue())
        elif path == "/":
            handler._send(200, """
            <html><head><title>Company Portal</title></head>
            <body><h1>Internal Portal</h1></body></html>
            """)
        else:
            handler._send(404, "Not Found")


class SourceLeakEnvFile(ChallengeTarget):
    """Challenge: .env file exposed with flag in environment variable."""
    category = "source_leak"
    name = "source_leak_env_file"
    flag = "flag{env_f1l3_3xp0s3d_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path
        if path == "/.env":
            handler._send(200, f"""
            APP_ENV=production
            DB_HOST=localhost
            DB_USER=admin
            DB_PASS=secret123
            FLAG={self.flag}
            SECRET_KEY=s3cr3tk3y
            """, "text/plain")
        elif path == "/":
            handler._send(200, """
            <html><head><title>Laravel App</title></head>
            <body><h1>Laravel</h1><p>The application is running.</p></body></html>
            """)
        else:
            handler._send(404, "Not Found")


# ============================================================================
# LFI challenges (3)
# ============================================================================

class LFIReadDirect(ChallengeTarget):
    """Challenge: ?page= param directly includes files, flag at /flag."""
    category = "lfi"
    name = "lfi_read_direct"
    flag = "flag{lfi_d1r3ct_r34d_2024}"
    _flag_path = "/tmp/benchmark_flag_lfi"

    def __init__(self):
        super().__init__()
        # Write flag to a temp file
        Path(self._flag_path).write_text(self.flag)

    def cleanup(self):
        try:
            Path(self._flag_path).unlink(missing_ok=True)
        except Exception:
            pass

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        page = params.get("page", [None])[0]
        if page:
            try:
                content = Path(page).read_text()
                handler._send(200, f"<html><body><pre>{content}</pre></body></html>")
            except FileNotFoundError:
                handler._send(200, f"<html><body><p>File not found: {page}</p></body></html>")
            except Exception:
                handler._send(200, "<html><body><p>Error reading file</p></body></html>")
        else:
            handler._send(200, """
            <html><body><h1>Document Viewer</h1>
            <ul><li><a href='/?page=/etc/hosts'>Hosts</a></li>
            <li><a href='/?page=/tmp/benchmark_flag_lfi'>Flag Doc</a></li></ul>
            </body></html>
            """)


class LFIReadPhpFilter(ChallengeTarget):
    """Challenge: ?file= param, flag in PHP source comment, need php://filter."""
    category = "lfi"
    name = "lfi_php_filter"
    flag = "flag{php_f1lt3r_b4s364_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        file = params.get("file", [None])[0]
        if file and file.startswith("php://filter"):
            # Simulate php://filter base64 behavior
            import base64
            source = f"<?php\n// SECRET FLAG: {self.flag}\n$user = 'admin';\n?>"
            encoded = base64.b64encode(source.encode()).decode()
            handler._send(200, encoded, "text/plain")
        elif file:
            handler._send(200, f"<html><body><p>Reading: {file}</p></body></html>")
        else:
            handler._send(200, """
            <html><body><h1>File Viewer</h1>
            <form action="/" method="GET">
            <input name="file" placeholder="Enter file path">
            <button type="submit">View</button></form>
            </body></html>
            """)


class LFIReadEncoded(ChallengeTarget):
    """Challenge: LFI with basic filtering, need encoding bypass."""
    category = "lfi"
    name = "lfi_encoded_bypass"
    flag = "flag{lfi_3nc0d3d_byp4ss_2024}"
    _flag_path = "/tmp/benchmark_flag_lfi2"

    def __init__(self):
        super().__init__()
        Path(self._flag_path).write_text(self.flag)

    def cleanup(self):
        try:
            Path(self._flag_path).unlink(missing_ok=True)
        except Exception:
            pass

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        path = params.get("path", [None])[0]
        if path:
            # Block direct "../" but allow double-encoded
            if "../" in path and "..%2f" not in path and "..%252f" not in path:
                handler._send(403, "Blocked: path traversal detected")
                return
            # Decode double encoding
            decoded = path.replace("%252f", "/").replace("%2f", "/")
            try:
                content = Path(decoded).read_text()
                handler._send(200, f"<pre>{content}</pre>")
            except Exception:
                handler._send(200, f"File not found: {decoded}")
        else:
            handler._send(200, """
            <html><body><h1>Doc Viewer v2</h1>
            <a href='/?path=/etc/hostname'>View Hostname</a>
            </body></html>
            """)


# ============================================================================
# SSTI challenges (3)
# ============================================================================

class SSTIReflectedJinja2(ChallengeTarget):
    """Challenge: ?name= param rendered in Jinja2 template, no filtering."""
    category = "ssti"
    name = "ssti_jinja2"
    flag = "flag{ssti_j1nj42_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        name = params.get("name", ["Guest"])[0]

        # Simple Jinja2-style rendering
        if "{{" in name:
            # Evaluate basic SSTI probes
            if "7*7" in name:
                handler._send(200, f"<html><body><h1>Hello, 49!</h1></body></html>")
            elif "config" in name:
                handler._send(200, f"<html><body><h1>Hello, Config: flag={self.flag}</h1></body></html>")
            elif "flag" in name.lower() or "read" in name:
                handler._send(200, f"<html><body><h1>Hello, {self.flag}</h1></body></html>")
            else:
                handler._send(200, f"<html><body><h1>Hello, EVAL!</h1></body></html>")
        else:
            handler._send(200, f"<html><body><h1>Hello, {name}!</h1></body></html>")


class SSTITwigFiltered(ChallengeTarget):
    """Challenge: Twig template with some filtering on {{ }}."""
    category = "ssti"
    name = "ssti_twig"
    flag = "flag{tw1g_sst1_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        message = params.get("message", ["Hello"])[0]

        if "${" in message or "{{" in message:
            if "7*7" in message:
                handler._send(200, f"<html><body><p>49</p></body></html>")
            elif "flag" in message.lower():
                handler._send(200, f"<html><body><p>{self.flag}</p></body></html>")
            else:
                handler._send(200, f"<html><body><p>Template output: {message}</p></body></html>")
        else:
            handler._send(200, f"<html><body><p>Message: {message}</p></body></html>")


class SSTISmartyFiltered(ChallengeTarget):
    """Challenge: Smarty template, needs specific delimiter bypass."""
    category = "ssti"
    name = "ssti_smarty"
    flag = "flag{sm4rty_sst1_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        template = params.get("template", ["index.tpl"])[0]

        if "7*7" in template or "49" in template:
            handler._send(200, f"<html><body><p>Template result: 49</p></body></html>")
        elif "flag" in template.lower() or "system" in template:
            handler._send(200, f"<html><body><p>Template result: {self.flag}</p></body></html>")
        else:
            handler._send(200, f"<html><body><p>Loading template: {template}</p></body></html>")


# ============================================================================
# SQLi challenges (4)
# ============================================================================

class SQLiErrorBased(ChallengeTarget):
    """Challenge: ?id= param with error-based SQL injection."""
    category = "sqli"
    name = "sqli_error_based"
    flag = "flag{sqli_3rr0r_b4s3d_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        pid = params.get("id", ["1"])[0]

        if "'" in pid or '"' in pid:
            handler._send(200, f"""
            <html><body><h1>Error</h1>
            <p>SQL Error: You have an error in your SQL syntax near '{pid}' at line 1</p>
            <p>MySQL version 8.0.35</p>
            </body></html>
            """)
        elif "UNION" in pid.upper():
            handler._send(200, f"""
            <html><body><h1>Search Results</h1>
            <p>{self.flag} | admin | admin@ctf.local</p>
            </body></html>
            """)
        elif pid.isdigit():
            handler._send(200, f"""
            <html><body><h1>User Profile</h1>
            <p>ID: {pid}</p><p>Name: User_{pid}</p>
            </body></html>
            """)
        else:
            handler._send(200, f"""
            <html><body><h1>No Results</h1></body></html>
            """)


class SQLiUnionBased(ChallengeTarget):
    """Challenge: ?q= param with UNION-based injection."""
    category = "sqli"
    name = "sqli_union_based"
    flag = "flag{sqli_un10n_b4s3d_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        q = params.get("q", [""])[0]

        if "'" in q:
            if "UNION" in q.upper() and "SELECT" in q.upper():
                handler._send(200, f"""
                <html><body><h1>Search</h1>
                <table><tr><td>1</td><td>{self.flag}</td><td>admin</td></tr></table>
                </body></html>
                """)
            else:
                handler._send(200, """
                <html><body><h1>Error</h1>
                <p>SQLite3::query(): Unable to prepare statement</p>
                </body></html>
                """)
        else:
            handler._send(200, f"""
            <html><body><h1>Search Results</h1>
            <p>No products found for: {q}</p>
            </body></html>
            """)


class SQLiBooleanBlind(ChallengeTarget):
    """Challenge: Boolean-based blind SQLi, response length differs."""
    category = "sqli"
    name = "sqli_boolean_blind"
    flag = "flag{sqli_b00l34n_bl1nd_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        uid = params.get("user_id", ["1"])[0]

        # Simulate boolean blind: if "true" condition detected, show more data
        # Simple heuristic: "OR '1'='1" or longer response
        if "OR" in uid.upper() and ("1=1" in uid.lower() or "'1'" in uid):
            handler._send(200, f"""
            <html><body><h1>Profile</h1>
            <p>User: admin</p><p>Flag: {self.flag}</p><p>Role: admin</p>
            </body></html>
            """)
        elif uid.isdigit():
            handler._send(200, f"""
            <html><body><h1>Profile</h1><p>User ID: {uid}</p></body></html>
            """)
        else:
            handler._send(200, "<html><body><h1>Profile</h1><p>Invalid user ID</p></body></html>")


class SQLiTimeBlind(ChallengeTarget):
    """Challenge: Time-based blind SQLi with SLEEP."""
    category = "sqli"
    name = "sqli_time_blind"
    flag = "flag{sqli_t1m3_bl1nd_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        pid = params.get("product_id", ["1"])[0]

        if "SLEEP" in pid.upper() or "sleep" in pid.lower():
            import time
            time.sleep(2)
            handler._send(200, f"""
            <html><body><h1>Product Info</h1>
            <p>Product: Widget</p><p>Flag: {self.flag}</p>
            </body></html>
            """)
        elif pid.isdigit():
            handler._send(200, f"<html><body><h1>Product #{pid}</h1><p>Widget</p></body></html>")
        else:
            handler._send(200, "<html><body><h1>Product Not Found</h1></body></html>")


# ============================================================================
# CMDi challenges (3)
# ============================================================================

class CMDiBasicSemicolon(ChallengeTarget):
    """Challenge: ?cmd= param, basic command injection with ; separator."""
    category = "cmdi"
    name = "cmdi_semicolon"
    flag = "flag{cmdi_s3m1c0l0n_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        cmd = params.get("cmd", ["date"])[0]

        if "cat" in cmd and "flag" in cmd:
            handler._send(200, f"<pre>{self.flag}\n</pre>")
        elif "id" in cmd:
            handler._send(200, "<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)\n</pre>")
        elif "ls" in cmd:
            handler._send(200, "<pre>index.php\nflag.txt\n</pre>")
        else:
            handler._send(200, f"<html><body><h1>Network Tools</h1><p>Command: ping -c 1 {cmd}</p></body></html>")


class CMDiFilteredChars(ChallengeTarget):
    """Challenge: CMDi with blacklist filtering (; | & blocked)."""
    category = "cmdi"
    name = "cmdi_filtered"
    flag = "flag{cmdi_f1lt3r_byp4ss_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        host = params.get("host", ["localhost"])[0]

        blocked = [";", "|", "&"]
        if any(b in host for b in blocked):
            handler._send(403, "Blocked: invalid character detected")
        elif "cat" in host and "flag" in host:
            handler._send(200, f"<pre>{self.flag}\n</pre>")
        elif "id" in host:
            handler._send(200, "<pre>uid=33(www-data)</pre>")
        else:
            handler._send(200, f"<html><body><h1>Ping Tool</h1><p>Pinging {host}...</p></body></html>")


class CMDiNoEcho(ChallengeTarget):
    """Challenge: Blind CMDi, no output — use sleep or out-of-band."""
    category = "cmdi"
    name = "cmdi_no_echo"
    flag = "flag{cmdi_bl1nd_00b_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        ip = params.get("ip", ["8.8.8.8"])[0]

        if "sleep" in ip.lower():
            import time
            time.sleep(3)
            handler._send(200, f"<html><body><h1>Ping Result</h1><p>4 packets transmitted</p></body></html>")
        elif "flag" in ip.lower():
            # Simulate out-of-band: write flag to accessible endpoint
            handler._send(200, f"""
            <html><body><h1>Ping Result</h1><p>64 bytes from {self.flag}</p></body></html>
            """)
        else:
            handler._send(200, f"<html><body><h1>Ping Result</h1><p>Pinging {ip}...</p></body></html>")


# ============================================================================
# SSRF challenges (3)
# ============================================================================

class SSRFLocalhostFlag(ChallengeTarget):
    """Challenge: SSRF via ?url= to access internal /flag endpoint."""
    category = "ssrf"
    name = "ssrf_localhost_flag"
    flag = "flag{ssrf_l0c4lh0st_2024}"
    _internal_flag = False

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        url = params.get("url", [None])[0]
        path = urlparse(handler.path).path

        if path == "/internal/flag":
            # Internal endpoint — only accessible from localhost
            if handler.client_address[0] == "127.0.0.1":
                handler._send(200, f'{{"flag": "{self.flag}"}}', "application/json")
            else:
                handler._send(403, "Access denied: internal only")
        elif url:
            # SSRF: fetch the URL and return content
            handler._send(200, f"""
            <html><body><h1>URL Fetcher</h1>
            <p>Fetching: {url}</p>
            <p>Result: flag={self.flag} (internal content)</p>
            </body></html>
            """)
        else:
            handler._send(200, """
            <html><body><h1>Content Fetcher</h1>
            <form><input name="url" placeholder="Enter URL">
            <button>Fetch</button></form></body></html>
            """)


class SSRFCloudMetadata(ChallengeTarget):
    """Challenge: SSRF to cloud metadata endpoint."""
    category = "ssrf"
    name = "ssrf_metadata"
    flag = "flag{ssrf_m3t4d4t4_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        url = params.get("url", [None])[0]
        path = urlparse(handler.path).path

        if path == "/latest/meta-data/":
            handler._send(200, "instance-id\npublic-keys/\nuser-data\n", "text/plain")
        elif path == "/latest/meta-data/user-data":
            handler._send(200, f"#!/bin/bash\necho '{self.flag}' > /var/www/flag.txt\n", "text/plain")
        elif url:
            handler._send(200, f"<html><body><p>URL content: {url}</p></body></html>")
        else:
            handler._send(200, """
            <html><body><h1>Web Proxy</h1>
            <form><input name="url" placeholder="http://example.com">
            <button>Proxy</button></form></body></html>
            """)


class SSRFFileProtocol(ChallengeTarget):
    """Challenge: SSRF supporting file:// protocol."""
    category = "ssrf"
    name = "ssrf_file_protocol"
    flag = "flag{ssrf_f1l3_pr0t0c0l_2024}"
    _flag_path = "/tmp/benchmark_ssrf_flag"

    def __init__(self):
        super().__init__()
        Path(self._flag_path).write_text(self.flag)

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        url = params.get("url", [None])[0]

        if url:
            if url.startswith("file://"):
                try:
                    filepath = url[7:]
                    content = Path(filepath).read_text()
                    handler._send(200, f"<pre>{content}</pre>")
                except Exception as e:
                    handler._send(200, f"Error: {e}")
            else:
                handler._send(200, f"<html><body><p>Proxied: {url}</p></body></html>")
        else:
            handler._send(200, """
            <html><body><h1>Image Proxy</h1>
            <p>Usage: /?url=http://example.com/image.jpg</p>
            </body></html>
            """)


# ============================================================================
# JWT challenges (3)
# ============================================================================

class JWTAlgNone(ChallengeTarget):
    """Challenge: JWT with alg=none acceptance."""
    category = "jwt"
    name = "jwt_alg_none"
    flag = "flag{jwt_n0n3_4lg_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        auth = handler.headers.get("Authorization", "")
        cookie = handler.headers.get("Cookie", "")
        path = urlparse(handler.path).path

        if path == "/admin":
            # Check for valid JWT (accepts alg=none)
            if "eyJ" in auth or "eyJ" in cookie:
                handler._send(200, f"""
                <html><body><h1>Admin Panel</h1>
                <p>Welcome admin!</p><p>Flag: {self.flag}</p>
                </body></html>
                """)
            else:
                handler._send(401, "Unauthorized — provide JWT token")
        else:
            # Set a sample JWT cookie
            import base64
            header = base64.urlsafe_b64encode(
                json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payload = base64.urlsafe_b64encode(
                json.dumps({"user": "guest", "role": "user"}).encode()
            ).rstrip(b"=").decode()
            handler.send_response(200)
            handler.send_header("Set-Cookie", f"token={header}.{payload}.signature; Path=/")
            handler.send_header("Content-Type", "text/html")
            handler.end_headers()
            handler.wfile.write(b"""
            <html><body><h1>Welcome</h1>
            <p>You are logged in as guest. <a href="/admin">Admin Panel</a></p>
            </body></html>
            """)


class JWTWeakKey(ChallengeTarget):
    """Challenge: JWT with weak HMAC key ('secret')."""
    category = "jwt"
    name = "jwt_weak_key"
    flag = "flag{jwt_w34k_k3y_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        import base64
        import hmac
        import hashlib

        auth = handler.headers.get("Authorization", "")
        path = urlparse(handler.path).path

        if path == "/flag":
            if "Bearer " in auth:
                token = auth[7:]
                parts = token.split(".")
                if len(parts) == 3:
                    try:
                        header_b64, payload_b64, sig_b64 = parts
                        data = f"{header_b64}.{payload_b64}"
                        # Verify with key="secret"
                        expected_sig = base64.urlsafe_b64encode(
                            hmac.new(b"secret", data.encode(), hashlib.sha256).digest()
                        ).rstrip(b"=").decode()
                        if sig_b64 == expected_sig:
                            decoded_payload = base64.urlsafe_b64decode(
                                payload_b64 + "=" * (4 - len(payload_b64) % 4)
                            )
                            payload = json.loads(decoded_payload)
                            if payload.get("role") == "admin":
                                handler._send(200, f'{{"flag": "{self.flag}"}}', "application/json")
                                return
                    except Exception:
                        pass
            handler._send(403, "Invalid admin token")
        else:
            handler._send(200, """
            <html><body><h1>API</h1>
            <p>GET /flag — requires admin JWT (HS256, key='secret')</p>
            </body></html>
            """)


class JWTKidInjection(ChallengeTarget):
    """Challenge: JWT with kid parameter vulnerable to path traversal."""
    category = "jwt"
    name = "jwt_kid_injection"
    flag = "flag{jwt_k1d_1nj3ct_2024}"
    _key_path = "/tmp/benchmark_jwt_key"

    def __init__(self):
        super().__init__()
        Path(self._key_path).write_text("kid_secret_key\n")

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path
        if path == "/admin":
            auth = handler.headers.get("Authorization", "")
            if "eyJ" in auth:
                handler._send(200, f'{{"flag": "{self.flag}"}}', "application/json")
            else:
                handler._send(401, "Authorization required")
        else:
            handler._send(200, """
            <html><body><h1>JWT Auth Demo</h1>
            <p>API uses JWT with kid header for key selection.</p>
            </body></html>
            """)


# ============================================================================
# Upload challenges (3)
# ============================================================================

class UploadMimeCheck(ChallengeTarget):
    """Challenge: File upload with only MIME type check."""
    category = "upload"
    name = "upload_mime_check"
    flag = "flag{upl04d_m1m3_2024}"
    _uploaded_content: Dict[str, bytes] = {}

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path
        if path.startswith("/uploads/") and path[9:] in self._uploaded_content:
            content = self._uploaded_content[path[9:]]
            if path.endswith(".php"):
                # Execute PHP if it contains system()
                handler._send(200, f"PHP executed: {self.flag}")
            else:
                handler._send(200, content.decode("utf-8", errors="replace"), "text/plain")
        else:
            handler._send(200, """
            <html><body><h1>Upload</h1>
            <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="file"><button>Upload</button></form>
            </body></html>
            """)

    def handle_POST(self, handler: ChallengeHandler):
        content_type = handler.headers.get("Content-Type", "")
        if "multipart" not in content_type:
            handler._send(400, "Bad Request")
            return

        # Simple multipart parse
        body = handler._read_body()
        # Extract filename and content very simply
        body_str = body.decode("utf-8", errors="replace")
        filename = "uploaded.txt"
        if 'filename="' in body_str:
            start = body_str.index('filename="') + 10
            end = body_str.index('"', start)
            filename = body_str[start:end]

        # Extract binary content after \r\n\r\n
        if b"\r\n\r\n" in body:
            content = body.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        else:
            content = b""

        self._uploaded_content[filename] = content
        handler._send(200, f"""
        <html><body><h1>Uploaded!</h1>
        <p>File: {filename}</p>
        <p>Size: {len(content)} bytes</p>
        <p>URL: <a href='/uploads/{filename}'>/uploads/{filename}</a></p>
        </body></html>
        """)


class UploadDoubleExt(ChallengeTarget):
    """Challenge: File upload with extension blacklist, bypass with .php.jpg."""
    category = "upload"
    name = "upload_double_ext"
    flag = "flag{upl04d_d0ubl3_2024}"
    _uploaded: Dict[str, bytes] = {}

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path
        if path.startswith("/files/") and path[7:] in self._uploaded:
            content = self._uploaded[path[7:]]
            if path.endswith(".php") or ".php." in path:
                handler._send(200, f"PHP executed: {self.flag}")
            else:
                handler._send(200, content.decode("utf-8", errors="replace"), "text/plain")
        else:
            handler._send(200, """
            <html><body><h1>File Upload</h1>
            <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="image"><button>Upload Image</button></form>
            </body></html>
            """)

    def handle_POST(self, handler: ChallengeHandler):
        body = handler._read_body()
        body_str = body.decode("utf-8", errors="replace")

        filename = "image.png"
        if 'filename="' in body_str:
            start = body_str.index('filename="') + 10
            end = body_str.index('"', start)
            filename = body_str[start:end]

        # Blacklist: block .php but allow .php.jpg
        if filename.endswith(".php") and not any(filename.endswith(ext) for ext in [".php.jpg", ".php.png", ".php.gif"]):
            handler._send(403, "Blocked: PHP files not allowed")
            return

        if b"\r\n\r\n" in body:
            content = body.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        else:
            content = b""

        self._uploaded[filename] = content
        handler._send(200, f"""
        <html><body><h1>Upload OK</h1>
        <p>Saved to /files/{filename}</p>
        </body></html>
        """)


class UploadHtaccess(ChallengeTarget):
    """Challenge: Upload with .htaccess + custom extension (two-step)."""
    category = "upload"
    name = "upload_htaccess"
    flag = "flag{upl04d_ht4cc3ss_2024}"
    _files: Dict[str, bytes] = {}
    _htaccess_content: Optional[bytes] = None

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path
        if path.startswith("/uploads/"):
            fname = path[9:]
            if fname in self._files:
                content = self._files[fname]
                # If .htaccess sets .txt as PHP handler
                if self._htaccess_content and b"AddType" in self._htaccess_content:
                    if fname.endswith(".txt"):
                        handler._send(200, f"PHP executed via .htaccess: {self.flag}")
                        return
                    if fname.endswith(".php"):
                        handler._send(200, f"PHP executed: {self.flag}")
                        return
                handler._send(200, content.decode("utf-8", errors="replace"), "text/plain")
            else:
                handler._send(404, "File not found")
        else:
            handler._send(200, """
            <html><body><h1>Upload (Apache)</h1>
            <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="file"><button>Upload</button></form>
            </body></html>
            """)

    def handle_POST(self, handler: ChallengeHandler):
        body = handler._read_body()
        body_str = body.decode("utf-8", errors="replace")
        filename = "uploaded.txt"
        if 'filename="' in body_str:
            start = body_str.index('filename="') + 10
            end = body_str.index('"', start)
            filename = body_str[start:end]

        if b"\r\n\r\n" in body:
            content = body.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        else:
            content = b""

        if filename == ".htaccess":
            self._htaccess_content = content
        self._files[filename] = content
        handler._send(200, f"Uploaded: {filename} → /uploads/{filename}")


# ============================================================================
# PHP POP challenges (2)
# ============================================================================

class PHPPopUnserializeCookie(ChallengeTarget):
    """Challenge: PHP app that unserializes cookie data."""
    category = "php_pop"
    name = "php_pop_cookie"
    flag = "flag{php_p0p_un53r14l1z3_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        cookie = handler.headers.get("Cookie", "")
        path = urlparse(handler.path).path

        if path == "/admin" and "user=" in cookie:
            user_data = None
            for c in cookie.split(";"):
                if c.strip().startswith("user="):
                    user_data = c.strip()[5:]
            if user_data and "admin" in user_data:
                handler._send(200, f"""
                <html><body><h1>Admin Panel</h1>
                <p>Welcome admin!</p><p>Flag: {self.flag}</p>
                </body></html>
                """)
                return
            handler._send(403, "Admin access required")

        handler.send_response(200)
        handler.send_header("Set-Cookie", "user=s:5:\"guest\"; Path=/")
        handler.send_header("Content-Type", "text/html")
        handler.end_headers()
        handler.wfile.write(b"""
        <html><body><h1>PHP App</h1>
        <p>Logged in as guest. <a href="/admin">Admin</a></p>
        <p><small>Session stored in cookie (unserialized via unserialize())</small></p>
        </body></html>
        """)


class PHPPopPharTrigger(ChallengeTarget):
    """Challenge: file_exists() on user input triggers phar:// deserialization."""
    category = "php_pop"
    name = "php_pop_phar"
    flag = "flag{php_ph4r_tr1gg3r_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        file = params.get("file", [None])[0]
        path = urlparse(handler.path).path

        if path == "/check" and file:
            # Simulate: file_exists("uploads/" . $filename)
            if "phar://" in file:
                handler._send(200, f"""
                <html><body><h1>File Check</h1>
                <p>Phar triggered!</p><p>Flag: {self.flag}</p>
                </body></html>
                """)
            else:
                handler._send(200, f"""
                <html><body><h1>File Check</h1>
                <p>Checking: uploads/{file}</p><p>Exists: True</p>
                </body></html>
                """)
        else:
            handler._send(200, """
            <html><body><h1>File Checker</h1>
            <p><a href="/check?file=test.txt">Check test.txt</a></p>
            <p><small>Uses file_exists() on uploads/ directory</small></p>
            </body></html>
            """)


# ============================================================================
# IDOR challenges (2)
# ============================================================================

class IDORNumeric(ChallengeTarget):
    """Challenge: IDOR with numeric IDs, /api/user/1/profile."""
    category = "idor"
    name = "idor_numeric"
    flag = "flag{1d0r_num3r1c_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path

        if path.startswith("/api/user/") and path.endswith("/profile"):
            try:
                user_id = int(path.split("/")[3])
                if user_id == 0:  # admin user
                    handler._send(200, f"""
                    {{"id": 0, "name": "admin", "role": "admin", "flag": "{self.flag}"}}
                    """, "application/json")
                elif user_id == 1:
                    handler._send(200, '{"id": 1, "name": "alice", "role": "user"}', "application/json")
                elif user_id == 2:
                    handler._send(200, '{"id": 2, "name": "bob", "role": "user"}', "application/json")
                else:
                    handler._send(404, '{"error": "User not found"}')
            except (ValueError, IndexError):
                handler._send(400, '{"error": "Invalid user ID"}')
        else:
            handler._send(200, """
            <html><body><h1>User API</h1>
            <p>GET /api/user/1/profile — View your profile</p>
            <p>Logged in as: alice (ID: 1)</p>
            </body></html>
            """)


class IDORUUID(ChallengeTarget):
    """Challenge: IDOR with UUID-based object references."""
    category = "idor"
    name = "idor_uuid"
    flag = "flag{1d0r_uu1d_2024}"
    _admin_uuid = "00000000-0000-0000-0000-000000000000"
    _user_uuid = "11111111-1111-1111-1111-111111111111"

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path

        if path.startswith("/api/orders/"):
            order_id = path.split("/")[3]
            if order_id == self._admin_uuid:
                handler._send(200, f"""
                {{"order_id": "{order_id}", "user": "admin", "total": 0, "flag": "{self.flag}"}}
                """, "application/json")
            elif order_id == self._user_uuid:
                handler._send(200, f"""
                {{"order_id": "{order_id}", "user": "alice", "total": 100}}
                """, "application/json")
            else:
                handler._send(404, '{"error": "Order not found"}')
        else:
            handler._send(200, f"""
            <html><body><h1>Order System</h1>
            <p>Your orders:</p>
            <ul><li><a href="/api/orders/{self._user_uuid}">Order #{self._user_uuid[:8]}</a></li></ul>
            </body></html>
            """)


# ============================================================================
# XSS challenges (2)
# ============================================================================

class XSSReflected(ChallengeTarget):
    """Challenge: Reflected XSS + admin bot with flag in cookie."""
    category = "xss"
    name = "xss_reflected"
    flag = "flag{xss_r3fl3ct3d_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        params = handler._parse_query()
        query = params.get("q", [""])[0]
        path = urlparse(handler.path).path

        if path == "/admin/bot":
            # Admin bot: visits URL and checks for flag steal
            url = params.get("visit", [""])[0]
            if "document.cookie" in url or "fetch" in url:
                handler._send(200, f"""
                <html><body><h1>Bot Result</h1>
                <p>Admin bot visited: {url}</p>
                <p>Admin cookie contained: flag={self.flag}</p>
                </body></html>
                """)
            else:
                handler._send(200, """
                <html><body><h1>Admin Bot</h1>
                <form><input name="visit" placeholder="URL to visit">
                <button>Submit to Admin</button></form></body></html>
                """)
        else:
            # Reflected XSS: user input reflected in page
            handler._send(200, f"""
            <html><body><h1>Search Results</h1>
            <p>Results for: {query}</p>
            <p>No results found.</p>
            <p><small>Report issues to <a href="/admin/bot">Admin Bot</a></small></p>
            </body></html>
            """)


class XSSStored(ChallengeTarget):
    """Challenge: Stored XSS in guestbook, admin bot reads messages."""
    category = "xss"
    name = "xss_stored"
    flag = "flag{xss_st0r3d_2024}"
    _messages: List[str] = []

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path

        if path == "/admin/read":
            # Admin reads guestbook messages
            msg_list = "".join(f"<li>{m}</li>" for m in self._messages)
            # If any message looks like XSS stealing cookie, expose flag
            if any("cookie" in m.lower() or "fetch" in m.lower() for m in self._messages):
                handler._send(200, f"""
                <html><body><h1>Admin Messages</h1>
                <ul>{msg_list}</ul>
                <p>Admin cookie: flag={self.flag}</p>
                </body></html>
                """)
            else:
                handler._send(200, f"""
                <html><body><h1>Admin Messages</h1>
                <ul>{msg_list}</ul>
                </body></html>
                """)
        else:
            msg_list = "".join(f"<li>{m}</li>" for m in self._messages)
            handler._send(200, f"""
            <html><body><h1>Guestbook</h1>
            <ul>{msg_list}</ul>
            <form method="POST"><input name="message"><button>Post</button></form>
            <p><small>Admin reviews messages at <a href="/admin/read">/admin/read</a></small></p>
            </body></html>
            """)

    def handle_POST(self, handler: ChallengeHandler):
        body = handler._read_body()
        body_str = body.decode("utf-8", errors="replace")
        params = parse_qs(body_str)
        message = params.get("message", [""])[0]
        if message:
            self._messages.append(message)
        handler.send_response(302)
        handler.send_header("Location", "/")
        handler.end_headers()


# ============================================================================
# GraphQL/WebSocket challenges (2)
# ============================================================================

class GraphQLIntrospection(ChallengeTarget):
    """Challenge: GraphQL with introspection enabled, flag in hidden query."""
    category = "graphql"
    name = "graphql_introspection"
    flag = "flag{gr4phql_1ntr0sp3ct_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        handler._send(200, """
        <html><body><h1>GraphQL API</h1>
        <p>POST /graphql with GraphQL query</p>
        </body></html>
        """)

    def handle_POST(self, handler: ChallengeHandler):
        body = handler._read_body()
        try:
            query_data = json.loads(body)
            query = query_data.get("query", "")

            if "__schema" in query:
                handler._send(200, json.dumps({
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [
                                {"name": "Query", "fields": [
                                    {"name": "user"},
                                    {"name": "getFlag"},
                                    {"name": "system"}
                                ]}
                            ]
                        }
                    }
                }), "application/json")
            elif "getFlag" in query:
                handler._send(200, json.dumps({
                    "data": {"getFlag": self.flag}
                }), "application/json")
            elif "user" in query:
                handler._send(200, json.dumps({
                    "data": {"user": {"id": 1, "name": "admin"}}
                }), "application/json")
            else:
                handler._send(200, json.dumps({
                    "data": {"__typename": "Query"}
                }), "application/json")
        except json.JSONDecodeError:
            handler._send(400, '{"error": "Invalid JSON"}')


class WebSocketAuthBypass(ChallengeTarget):
    """Challenge: WebSocket with message-level auth bypass."""
    category = "websocket"
    name = "websocket_auth_bypass"
    flag = "flag{w3bs0ck3t_4uth_2024}"

    def handle_GET(self, handler: ChallengeHandler):
        path = urlparse(handler.path).path

        if path == "/api/ws/connect":
            # Simulate WebSocket-like HTTP endpoint
            params = handler._parse_query()
            token = params.get("token", [""])[0]
            if token == "admin_token" or token == "admin":
                handler._send(200, json.dumps({
                    "status": "connected",
                    "role": "admin",
                    "flag": self.flag,
                }), "application/json")
            else:
                handler._send(200, json.dumps({
                    "status": "connected",
                    "role": "guest",
                    "note": "Need admin role for flag"
                }), "application/json")
        else:
            handler._send(200, """
            <html><body><h1>Real-time Chat</h1>
            <p>Connect: /api/ws/connect?token=guest</p>
            <p>Try admin privileges for full access.</p>
            </body></html>
            """)


# ============================================================================
# All challenges registry
# ============================================================================

ALL_CHALLENGES: Dict[str, type] = {
    # source_leak (3)
    "source_leak_git_head_01": SourceLeakGitHead,
    "source_leak_backup_zip_02": SourceLeakBackupZip,
    "source_leak_env_file_03": SourceLeakEnvFile,
    # LFI (3)
    "lfi_read_direct_01": LFIReadDirect,
    "lfi_php_filter_02": LFIReadPhpFilter,
    "lfi_encoded_bypass_03": LFIReadEncoded,
    # SSTI (3)
    "ssti_jinja2_01": SSTIReflectedJinja2,
    "ssti_twig_02": SSTITwigFiltered,
    "ssti_smarty_03": SSTISmartyFiltered,
    # SQLi (4)
    "sqli_error_based_01": SQLiErrorBased,
    "sqli_union_based_02": SQLiUnionBased,
    "sqli_boolean_blind_03": SQLiBooleanBlind,
    "sqli_time_blind_04": SQLiTimeBlind,
    # CMDi (3)
    "cmdi_semicolon_01": CMDiBasicSemicolon,
    "cmdi_filtered_02": CMDiFilteredChars,
    "cmdi_no_echo_03": CMDiNoEcho,
    # SSRF (3)
    "ssrf_localhost_flag_01": SSRFLocalhostFlag,
    "ssrf_metadata_02": SSRFCloudMetadata,
    "ssrf_file_protocol_03": SSRFFileProtocol,
    # JWT (3)
    "jwt_alg_none_01": JWTAlgNone,
    "jwt_weak_key_02": JWTWeakKey,
    "jwt_kid_injection_03": JWTKidInjection,
    # Upload (3)
    "upload_mime_check_01": UploadMimeCheck,
    "upload_double_ext_02": UploadDoubleExt,
    "upload_htaccess_03": UploadHtaccess,
    # PHP POP (2)
    "php_pop_cookie_01": PHPPopUnserializeCookie,
    "php_pop_phar_02": PHPPopPharTrigger,
    # IDOR (2)
    "idor_numeric_01": IDORNumeric,
    "idor_uuid_02": IDORUUID,
    # XSS (2)
    "xss_reflected_01": XSSReflected,
    "xss_stored_02": XSSStored,
    # GraphQL/WebSocket (2)
    "graphql_introspection_01": GraphQLIntrospection,
    "websocket_auth_bypass_02": WebSocketAuthBypass,
}
