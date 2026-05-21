"""Extra 15 real CTF challenge simulations — BUUCTF/classic Web challenges.

Challenges 6-20, extending the original 5 in real_ctf_targets.py.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict
from urllib.parse import parse_qs, urlparse, unquote


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ===========================================================================
# 6. [强网杯 2019] 随便注 — Stacked injection with handler bypass
# ===========================================================================

class QWB2019RandomInjectTarget:
    """Stacked injection where SELECT is blocked. Use handler/rename to read flag.

    Solution: 1';handler Flag open;handler Flag read first;
    """
    flag = "flag{qwb2019_rand0m_1nj3ct}"
    name = "qwb2019_random_inject"
    category = "sqli"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                body = """<html><head><title>随便注</title></head><body>
<h1>强网杯 2019 - 随便注</h1>
<form action="/" method="POST">
<input type="text" name="inject" placeholder="输入注入">
<input type="submit" value="提交">
</form>
<p>Hint: select/update/delete/drop/insert/where are blocked</p>
</body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace")
                params = parse_qs(body_str)
                inject = params.get("inject", [""])[0]

                blocked = ["select", "update", "delete", "drop", "insert", "where"]
                inject_lower = inject.lower()

                # Check for blocked keywords
                for kw in blocked:
                    if kw in inject_lower and "handler" not in inject_lower:
                        resp = "<html><body><p>return preg_match(\"/select|update|delete|drop|insert|where/i\")</p></body></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                        self.end_headers()
                        self.wfile.write(resp.encode())
                        return

                # Handler bypass: handler Flag open; handler Flag read first;
                if "handler" in inject_lower and "flag" in inject_lower:
                    resp = f"<html><body><p>Result: {parent.flag}</p></body></html>"
                # Rename bypass
                elif "rename" in inject_lower or "alter" in inject_lower:
                    resp = f"<html><body><p>Query OK. {parent.flag}</p></body></html>"
                else:
                    resp = "<html><body><p>Array ( [0] => 1 )</p></body></html>"

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(resp.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 7. [GYCTF2020] Blacklist — Similar to 随便注, handler bypass
# ===========================================================================

class GYCTF2020BlacklistTarget:
    """Stacked injection with more keywords blocked. Handler still works.

    Solution: 1';handler FlagHere open;handler FlagHere read first;
    """
    flag = "flag{gyctf2020_bl4ckl1st_byp4ss}"
    name = "gyctf2020_blacklist"
    category = "sqli"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                body = """<html><head><title>Blacklist</title></head><body>
<h1>GYCTF2020 - Blacklist</h1>
<form action="/" method="POST">
<input type="text" name="inject" placeholder="输入注入">
<input type="submit" value="提交">
</form>
<p>Hint: select/update/delete/drop/insert/where/set/prepare are blocked</p>
</body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace")
                params = parse_qs(body_str)
                inject = params.get("inject", [""])[0]

                inject_lower = inject.lower()
                blocked = ["select", "update", "delete", "drop", "insert",
                           "where", "set", "prepare"]

                for kw in blocked:
                    if kw in inject_lower and "handler" not in inject_lower:
                        resp = "<html><body><p>Blocked keyword detected!</p></body></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                        self.end_headers()
                        self.wfile.write(resp.encode())
                        return

                if "handler" in inject_lower and ("flag" in inject_lower or "flaghere" in inject_lower):
                    resp = f"<html><body><p>Result: {parent.flag}</p></body></html>"
                elif "rename" in inject_lower or "alter" in inject_lower:
                    resp = f"<html><body><p>Query OK. {parent.flag}</p></body></html>"
                else:
                    resp = "<html><body><p>Array ( [0] => 1 )</p></body></html>"

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(resp.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 8. [极客大挑战 2019] BabySQL — Double-write bypass
# ===========================================================================

class BabySQLTarget:
    """SQL injection with keyword filtering (removes once). Double-write bypass.

    Server removes: or, select, union, where, and, from
    Solution: admin' oorr '1'='1 or ununionion seselectlect 1,2,3-- -
    """
    flag = "flag{babysql_d0uble_wr1te_2019}"
    name = "geek2019_babysql"
    category = "sqli"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                params = parse_qs(parsed.query)

                if path == "/check.php":
                    username = params.get("username", [""])[0]
                    password = params.get("password", [""])[0]

                    # Server removes keywords ONCE (case-insensitive)
                    def filter_once(s):
                        for kw in ["or", "select", "union", "where", "and", "from"]:
                            s = re.sub(kw, "", s, flags=re.IGNORECASE)
                        return s

                    filtered_user = filter_once(username)
                    filtered_pass = filter_once(password)

                    # After filtering, check for SQL injection
                    sqli_patterns = [
                        "' or '1'='1", "' or 1=1", "or '1'='1",
                        "or 1=1", "'='", "admin'--", "admin'#",
                        "union select", "' or true",
                    ]
                    is_injected = any(
                        p in filtered_user.lower() or p in filtered_pass.lower()
                        for p in sqli_patterns
                    )

                    if is_injected:
                        body = f"<html><body><h1>Login Success!</h1><p>{parent.flag}</p></body></html>"
                    else:
                        body = "<html><body><h1>NO,Wrong username password！！！</h1></body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())
                else:
                    body = """<html><head><title>BabySQL</title></head><body>
<h1>极客大挑战 2019 - BabySQL</h1>
<p>听说你们都会SQL注入？这次过滤了关键字哦！</p>
<form action="check.php" method="GET">
<input type="text" name="username" placeholder="username">
<input type="password" name="password" placeholder="password">
<input type="submit" value="Login">
</form>
</body></html>"""
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 9. [极客大挑战 2019] Secret File — Hidden redirect + LFI
# ===========================================================================

class SecretFileTarget:
    """Hidden redirect to secr3t.php, then LFI via php://filter.

    Solution: GET /secr3t.php?file=php://filter/convert.base64-encode/resource=flag.php
    """
    flag = "flag{secr3t_f1le_lfi_2019}"
    name = "geek2019_secretfile"
    category = "lfi"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self
        flag_php_content = f"<?php $flag = '{parent.flag}'; ?>"
        flag_b64 = base64.b64encode(flag_php_content.encode()).decode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                params = parse_qs(parsed.query)

                if path == "/secr3t.php":
                    file_param = params.get("file", [None])[0]
                    if file_param:
                        # Check for php://filter
                        if "php://filter" in file_param.lower() and "flag" in file_param.lower():
                            body = flag_b64
                        elif "flag" in file_param.lower():
                            body = "<html><body><p>Cannot read PHP files directly!</p></body></html>"
                        else:
                            body = "<html><body><p>File not found</p></body></html>"
                    else:
                        body = """<html><body>
<p>secr3t.php - 你发现了秘密文件!</p>
<p>Take a look at the flag: <code>flag.php</code></p>
<p>Hint: use php://filter to read it</p>
<form><input name="file" placeholder="file="></form>
</body></html>"""
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())

                elif path == "/Archive_room.php":
                    # Quick redirect to end.php (the hidden redirect)
                    self.send_response(302)
                    self.send_header("Location", "/end.php")
                    self.end_headers()

                elif path == "/end.php":
                    body = "<html><body><p>没看清？回去再看看吧</p></body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(body.encode())

                else:
                    body = """<html><head><title>Secret File</title></head><body>
<h1>极客大挑战 2019 - Secret File</h1>
<p>我把flag藏在了一个秘密文件里</p>
<!-- secr3t.php -->
<a href="/Archive_room.php">SECRET</a>
</body></html>"""
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 10. [ACTF2020] Include — Simple php://filter include
# ===========================================================================

class ACTF2020IncludeTarget:
    """Simple php://filter LFI.

    Solution: GET /?file=php://filter/read=convert.base64-encode/resource=flag.php
    """
    flag = "flag{actf2020_1nclud3_php_f1lt3r}"
    name = "actf2020_include"
    category = "lfi"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self
        flag_php = f"<?php $flag = '{parent.flag}'; ?>"
        flag_b64 = base64.b64encode(flag_php.encode()).decode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                file_param = params.get("file", [None])[0]

                if file_param:
                    if "php://filter" in file_param.lower() and "flag" in file_param.lower():
                        body = flag_b64
                    elif "flag" in file_param.lower():
                        body = ""  # PHP file executed, no output
                    else:
                        body = "<html><body><p>File not found</p></body></html>"
                else:
                    body = """<html><head><title>Include</title></head><body>
<h1>ACTF2020 - Include</h1>
<p>Tips: php://filter</p>
<a href="/?file=flag.php">Can you find the flag?</a>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("X-Powered-By", "PHP/7.3.11")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 11. [BJDCTF2020] Easy MD5 — SQL injection via md5 raw output (ffifdyop)
# ===========================================================================

class EasyMD5Target:
    """SQL injection via md5($pass, true) producing 'or'6... raw bytes.

    Solution: password=ffifdyop (md5 raw output starts with 'or'6)
    """
    flag = "flag{bjdctf2020_e4sy_md5_r4w}"
    name = "bjdctf2020_easymd5"
    category = "sqli"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                password = params.get("password", [""])[0]

                if password:
                    # md5(ffifdyop, true) = 'or'6... which makes SQL true
                    raw_md5 = hashlib.md5(password.encode()).digest()
                    # Check if raw md5 contains 'or' pattern for SQL injection
                    if b"'or'" in raw_md5 or b"'or'" in raw_md5.lower() or password == "ffifdyop":
                        body = f"<html><body><h1>Login Success!</h1><p>{parent.flag}</p></body></html>"
                    else:
                        body = "<html><body><h1>Password Error!</h1></body></html>"
                else:
                    body = """<html><head><title>Easy MD5</title></head><body>
<h1>BJDCTF2020 - Easy MD5</h1>
<p>Hint: select * from 'admin' where password=md5($pass,true)</p>
<form action="/" method="GET">
<input type="text" name="password" placeholder="password">
<input type="submit" value="Login">
</form>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Hint", "select * from 'admin' where password=md5($pass,true)")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 12. [护网杯 2018] easy_tornado — Tornado SSTI via error page
# ===========================================================================

class EasyTornadoTarget:
    """Tornado SSTI via error page msg parameter.

    Solution: /error?msg={{handler.settings}} reveals flag
    """
    flag = "flag{tornado_sst1_h4ndl3r_2018}"
    name = "hwb2018_easy_tornado"
    category = "ssti"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                params = parse_qs(parsed.query)

                if path == "/error":
                    msg = params.get("msg", [""])[0]
                    # Simulate Tornado SSTI
                    if "handler.settings" in msg or "handler" in msg.lower():
                        body = f"<html><body><p>Error: {{'cookie_secret': '{parent.flag}'}}</p></body></html>"
                    elif "{{" in msg and "}}" in msg:
                        body = f"<html><body><p>Error: template expression evaluated</p></body></html>"
                    else:
                        body = f"<html><body><p>Error: {msg}</p></body></html>"
                elif path == "/flag.txt" or path == "/fllllllllllllag":
                    body = "<html><body><p>Need correct filehash to read this file</p></body></html>"
                else:
                    body = """<html><head><title>easy_tornado</title></head><body>
<h1>护网杯 2018 - easy_tornado</h1>
<a href="/flag.txt">flag.txt</a><br>
<a href="/welcome.txt">welcome.txt</a><br>
<a href="/hints.txt">hints.txt</a><br>
<p><!-- /error?msg=Error --></p>
<p>Hint: render(msg) on error page, try SSTI</p>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Server", "TornadoServer/5.1.1")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 13. [极客大挑战 2019] BuyFlag — Cookie + POST manipulation
# ===========================================================================

class BuyFlagTarget:
    """Cookie manipulation + is_numeric bypass.

    Solution: Cookie: user=1, POST: password=404&money[]=100000000
    """
    flag = "flag{buyflag_c00k1e_m4n1p_2019}"
    name = "geek2019_buyflag"
    category = "auth"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                body = """<html><head><title>BuyFlag</title></head><body>
<h1>极客大挑战 2019 - BuyFlag</h1>
<p>Flag costs 100000000 yuan</p>
<p>Only CUIT students can buy (Cookie: user=1)</p>
<p><!-- password is 404 but is_numeric blocks numbers --></p>
<form action="/pay.php" method="POST">
<input type="text" name="password" placeholder="password">
<input type="text" name="money" placeholder="money">
<input type="submit" value="Buy">
</form>
</body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Set-Cookie", "user=0")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                parsed = urlparse(self.path)
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace")
                params = parse_qs(body_str)

                cookie = self.headers.get("Cookie", "")
                # Check user cookie
                if "user=1" not in cookie:
                    resp = "<html><body><p>Only CUIT students can buy! Set Cookie: user=1</p></body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(resp.encode())
                    return

                password = params.get("password", [""])[0]
                money = params.get("money", params.get("money[]", [""]))[0]

                # Password check: must equal 404 (numeric comparison)
                if password != "404" and not password.startswith("404"):
                    resp = "<html><body><p>Wrong password!</p></body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(resp.encode())
                    return

                # Money check: is_numeric bypass — accept array or scientific notation
                # In PHP, money[]=100000000 bypasses is_numeric
                if "money[]" in body_str or "money%5B%5D" in body_str or "money%5b%5d" in body_str:
                    # Array bypass
                    resp = f"<html><body><h1>Success!</h1><p>{parent.flag}</p></body></html>"
                elif money and not money.isdigit():
                    # Scientific notation like 1e9
                    resp = f"<html><body><h1>Success!</h1><p>{parent.flag}</p></body></html>"
                elif money and int(money) >= 100000000:
                    # Direct large number (would be blocked by is_numeric in real PHP)
                    resp = "<html><body><p>Nope! is_numeric detected a number!</p></body></html>"
                else:
                    resp = "<html><body><p>Not enough money!</p></body></html>"

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(resp.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 14. [极客大挑战 2019] Http — HTTP header manipulation
# ===========================================================================

class HttpHeaderTarget:
    """Must send correct Referer + X-Forwarded-For headers.

    Solution: Referer: https://www.Sycsecret.com, X-Forwarded-For: 127.0.0.1
    """
    flag = "flag{http_h3ader_m4n1p_2019}"
    name = "geek2019_http"
    category = "auth"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path

                if path == "/Secret.php":
                    referer = self.headers.get("Referer", "")
                    xff = self.headers.get("X-Forwarded-For", "")

                    if "Sycsecret" not in referer and "sycsecret" not in referer.lower():
                        body = "<html><body><p>It doesn't come from 'https://www.Sycsecret.com'</p></body></html>"
                    elif "127.0.0.1" not in xff:
                        body = "<html><body><p>Please use local browser! (X-Forwarded-For: 127.0.0.1)</p></body></html>"
                    else:
                        body = f"<html><body><h1>Success!</h1><p>{parent.flag}</p></body></html>"
                else:
                    body = """<html><head><title>Http</title></head><body>
<h1>极客大挑战 2019 - Http</h1>
<p>兄弟你好，这里什么都没有</p>
<!-- Secret.php -->
<a href="/Secret.php">Secret</a>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 15. [极客大挑战 2019] EasyPHP — MD5 type juggling (0e collision)
# ===========================================================================

class EasyPHPTarget:
    """PHP type juggling: md5($a)==md5($b) with different values.

    Solution: a=QNKCDZO&b=240610708 (both md5 start with 0e → loose comparison true)
    """
    flag = "flag{easyphp_typ3_juggl1ng_2019}"
    name = "geek2019_easyphp"
    category = "php_pop"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self
        # Known 0e md5 values
        zero_e_values = {
            "QNKCDZO", "240610708", "s878926199a", "s155964671a",
            "s214587387a", "0e215962017",
        }

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                a = params.get("a", [None])[0]
                b = params.get("b", [None])[0]

                if a and b:
                    if a == b:
                        body = "<html><body><p>a and b must be different!</p></body></html>"
                    else:
                        md5_a = hashlib.md5(a.encode()).hexdigest()
                        md5_b = hashlib.md5(b.encode()).hexdigest()
                        # PHP loose comparison: 0e... == 0e... is true
                        a_is_0e = md5_a.startswith("0e") and md5_a[2:].isdigit()
                        b_is_0e = md5_b.startswith("0e") and md5_b[2:].isdigit()
                        if a_is_0e and b_is_0e:
                            body = f"<html><body><h1>Success!</h1><p>{parent.flag}</p></body></html>"
                        elif md5_a == md5_b:
                            body = f"<html><body><h1>Success!</h1><p>{parent.flag}</p></body></html>"
                        else:
                            body = f"<html><body><p>md5(a)={md5_a} != md5(b)={md5_b}</p></body></html>"
                else:
                    body = """<html><head><title>EasyPHP</title></head><body>
<h1>极客大挑战 2019 - EasyPHP</h1>
<p>Source:</p>
<pre>
if($a != $b && md5($a) == md5($b)) {
    echo $flag;
}
</pre>
<form action="/" method="GET">
<input type="text" name="a" placeholder="a">
<input type="text" name="b" placeholder="b">
<input type="submit" value="Check">
</form>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 16. [网鼎杯 2020] AreUSerialz — PHP unserialize with is_valid check
# ===========================================================================

class AreUSerialzTarget:
    """PHP unserialize with is_valid() check (only printable ASCII).

    Solution: Use S: (capital S) for hex escapes, or craft payload with only printable chars.
    Simplified: accept any serialized payload containing 'flag' and 'read' keywords.
    """
    flag = "flag{wdb2020_ar3u_s3r14lz}"
    name = "wdb2020_areuserialz"
    category = "php_pop"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                payload = params.get("str", [None])[0]

                if payload:
                    # is_valid check: only printable ASCII (32-126)
                    is_valid = all(32 <= ord(c) <= 126 for c in payload)

                    if not is_valid:
                        body = "<html><body><p>is_valid() check failed! Only printable ASCII allowed.</p></body></html>"
                    elif "FileHandler" in payload or ("read" in payload.lower() and "flag" in payload.lower()):
                        # Successful deserialization — reads flag
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                    elif "O:" in payload:
                        body = "<html><body><p>Deserialized but no flag read. Check your payload.</p></body></html>"
                    else:
                        body = "<html><body><p>Invalid serialized data</p></body></html>"
                else:
                    body = """<html><head><title>AreUSerialz</title></head><body>
<h1>网鼎杯 2020 - AreUSerialz</h1>
<pre>
class FileHandler {
    protected $op = 1;  // 1=write, 2=read
    protected $filename = "flag.php";
    protected $content;
    function process() {
        if($this->op == "2") $this->read();
    }
    function read() { echo file_get_contents($this->filename); }
}
// is_valid(): only chr(32)-chr(126) allowed
// Hint: use S: instead of s: for hex escapes
</pre>
<form action="/" method="GET">
<input type="text" name="str" placeholder="serialized payload" size="80">
<input type="submit" value="Unserialize">
</form>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 17. [De1CTF 2019] SSRF Me — Flask SSRF via geneSign + De1ta
# ===========================================================================

class SSRFMeTarget:
    """Flask SSRF: generate sign then use it to read flag.

    Solution: GET /geneSign?param=flag.txt to get sign, then GET /De1ta?param=flag.txt with sign cookie
    """
    flag = "flag{de1ctf2019_ssrf_m3_fl4sk}"
    name = "de1ctf2019_ssrfme"
    category = "ssrf"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None
        self._secret = "s3cr3t_k3y_de1ctf"

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                params = parse_qs(parsed.query)

                if path == "/geneSign":
                    param = params.get("param", [""])[0]
                    # Generate sign: md5(secret + param + "scan")
                    sign = hashlib.md5(
                        (parent._secret + param + "scan").encode()
                    ).hexdigest()
                    body = f"<html><body><p>Sign: {sign}</p></body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Set-Cookie", f"sign={sign}")
                    self.end_headers()
                    self.wfile.write(body.encode())

                elif path == "/De1ta":
                    param = params.get("param", [""])[0]
                    cookie = self.headers.get("Cookie", "")
                    # Extract sign from cookie
                    sign = ""
                    if "sign=" in cookie:
                        sign = cookie.split("sign=")[1].split(";")[0].strip()

                    # Verify sign
                    expected = hashlib.md5(
                        (parent._secret + param + "scan").encode()
                    ).hexdigest()

                    if sign == expected and "flag" in param.lower():
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                    elif sign == expected:
                        body = f"<html><body><p>File content: (empty)</p></body></html>"
                    else:
                        body = "<html><body><p>Invalid sign!</p></body></html>"

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(body.encode())

                else:
                    body = """<html><head><title>SSRF Me</title></head><body>
<h1>De1CTF 2019 - SSRF Me</h1>
<pre>
# Flask app source:
# /geneSign?param=xxx  → generates md5(secret+param+"scan")
# /De1ta?param=xxx     → reads file if sign cookie is valid
# Goal: read flag.txt
</pre>
<a href="/geneSign?param=flag.txt">Generate Sign for flag.txt</a><br>
<a href="/De1ta?param=flag.txt">Read flag.txt (need valid sign cookie)</a>
</body></html>"""
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 18. [NCTF2019] True XML cookbook — XXE injection
# ===========================================================================

class TrueXMLTarget:
    """XXE injection via XML login form.

    Solution: POST XML with <!ENTITY xxe SYSTEM "file:///flag"> in username
    """
    flag = "flag{nctf2019_xxe_xml_c00kb00k}"
    name = "nctf2019_truexml"
    category = "xxe"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                body = """<html><head><title>True XML cookbook</title></head><body>
<h1>NCTF2019 - True XML cookbook</h1>
<p>Login via XML</p>
<form id="loginform">
<input type="text" name="username" placeholder="username"><br>
<input type="password" name="password" placeholder="password"><br>
<button onclick="doLogin()">Login</button>
</form>
<script>
function doLogin() {
    var xml = '<user><username>' + document.querySelector('[name=username]').value +
              '</username><password>' + document.querySelector('[name=password]').value +
              '</password></user>';
    // POST as application/xml
    fetch('/', {method:'POST', headers:{'Content-Type':'application/xml'}, body:xml});
}
</script>
<p><!-- Hint: XML external entity injection --></p>
</body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace")

                # Check for XXE patterns
                if "ENTITY" in body_str or "SYSTEM" in body_str or "entity" in body_str:
                    # XXE detected — simulate file read
                    if "flag" in body_str.lower() or "file://" in body_str:
                        resp = f"<result><msg>Login failed</msg><username>{parent.flag}</username></result>"
                    elif "etc/passwd" in body_str:
                        resp = "<result><msg>Login failed</msg><username>root:x:0:0:root:/root:/bin/bash</username></result>"
                    else:
                        resp = "<result><msg>Login failed</msg><username>XXE processed</username></result>"
                elif "<user" in body_str or "<username" in body_str:
                    resp = "<result><msg>Login failed: wrong credentials</msg></result>"
                else:
                    resp = "<result><msg>Invalid XML format</msg></result>"

                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.end_headers()
                self.wfile.write(resp.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 19. [GXYCTF2019] Ping Ping Ping — CMDi with space blocked
# ===========================================================================

class PingPingPingTarget:
    """Command injection with space character blocked.

    Solution: ?ip=127.0.0.1;cat$IFS$9flag.php or ;cat${IFS}flag.php
    """
    flag = "flag{gxyctf2019_p1ng_p1ng_p1ng}"
    name = "gxyctf2019_pingpingping"
    category = "cmdi"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                ip = params.get("ip", [None])[0]

                if ip:
                    # Block spaces
                    if " " in ip:
                        body = "<html><body><p>fxck your space!</p></body></html>"
                    # Check for command injection with space bypass
                    elif any(sep in ip for sep in [";", "|", "`", "$("]):
                        # Extract the command part after separator
                        cmd_part = ip
                        for sep in [";", "|", "&&", "||"]:
                            if sep in cmd_part:
                                cmd_part = cmd_part.split(sep, 1)[1]
                                break

                        # Replace $IFS, ${IFS}, $IFS$9 with space for evaluation
                        cmd_eval = cmd_part.replace("$IFS$9", " ").replace("${IFS}", " ").replace("$IFS", " ").strip()

                        if "cat" in cmd_eval and "flag" in cmd_eval:
                            body = f"<html><body><pre>PING 127.0.0.1\n{parent.flag}</pre></body></html>"
                        elif "cat" in cmd_eval or "tac" in cmd_eval or "nl" in cmd_eval:
                            body = "<html><body><pre>PING 127.0.0.1\n(file content)</pre></body></html>"
                        else:
                            body = f"<html><body><pre>PING 127.0.0.1\n{cmd_eval}</pre></body></html>"
                    else:
                        body = f"<html><body><pre>PING {ip}\n64 bytes from {ip}: icmp_seq=1 ttl=64</pre></body></html>"
                else:
                    body = """<html><head><title>Ping Ping Ping</title></head><body>
<h1>GXYCTF2019 - Ping Ping Ping</h1>
<form action="/" method="GET">
<input type="text" name="ip" placeholder="ip">
<input type="submit" value="Ping">
</form>
<p>/?ip=127.0.0.1</p>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 20. [极客大挑战 2019] RCE Me — preg_match blocks all letters
# ===========================================================================

class RCEMeTarget:
    """RCE with all letters blocked by preg_match('/[a-z]/is').

    Solution: Use XOR/NOT to construct system('cat /flag') from non-alpha chars.
    Simplified: accept any input containing non-alpha chars that encodes to system/exec + flag.
    """
    flag = "flag{rceme_n0n_4lph4_rce_2019}"
    name = "geek2019_rceme"
    category = "cmdi"

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                code = params.get("code", [None])[0]

                if code:
                    # Check: no letters allowed
                    if re.search(r'[a-zA-Z]', code):
                        body = "<html><body><p>preg_match('/[a-z]/is') matched! No letters allowed!</p></body></html>"
                    else:
                        # Non-alpha code submitted — check if it's a valid XOR/NOT payload
                        # In real PHP, XOR of non-alpha chars can produce letters
                        # We accept: contains ^ or ~ operators (XOR/NOT), and is long enough
                        if ("^" in code or "~" in code or "%" in code) and len(code) > 10:
                            # Simulate successful RCE
                            body = f"<html><body><pre>{parent.flag}</pre></body></html>"
                        elif "$" in code and "(" in code:
                            # Variable function call pattern
                            body = f"<html><body><pre>{parent.flag}</pre></body></html>"
                        else:
                            body = "<html><body><p>Code executed but no output</p></body></html>"
                else:
                    body = """<html><head><title>RCE Me</title></head><body>
<h1>极客大挑战 2019 - RCE Me</h1>
<pre>
&lt;?php
if(isset($_GET['code'])){
    $code = $_GET['code'];
    if(preg_match('/[a-z]/is', $code)){
        die('hacker!');
    }
    eval($code);
}
?&gt;
</pre>
<form action="/" method="GET">
<input type="text" name="code" placeholder="code (no letters!)" size="60">
<input type="submit" value="Execute">
</form>
<p>Hint: use XOR (^) or NOT (~) to construct letters from non-alpha chars</p>
</body></html>"""

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# Registry of extra targets
# ===========================================================================

EXTRA_CTF_TARGETS = {
    "qwb2019_random_inject": QWB2019RandomInjectTarget,
    "gyctf2020_blacklist": GYCTF2020BlacklistTarget,
    "geek2019_babysql": BabySQLTarget,
    "geek2019_secretfile": SecretFileTarget,
    "actf2020_include": ACTF2020IncludeTarget,
    "bjdctf2020_easymd5": EasyMD5Target,
    "hwb2018_easy_tornado": EasyTornadoTarget,
    "geek2019_buyflag": BuyFlagTarget,
    "geek2019_http": HttpHeaderTarget,
    "geek2019_easyphp": EasyPHPTarget,
    "wdb2020_areuserialz": AreUSerialzTarget,
    "de1ctf2019_ssrfme": SSRFMeTarget,
    "nctf2019_truexml": TrueXMLTarget,
    "gxyctf2019_pingpingping": PingPingPingTarget,
    "geek2019_rceme": RCEMeTarget,
}
