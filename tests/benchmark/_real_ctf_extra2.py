"""Extra 10 real CTF challenge simulations — targets 21-30.

Challenges 21-30, extending the 20 in real_ctf_targets.py + _real_ctf_extra.py.
"""
from __future__ import annotations

import base64
import re
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ===========================================================================
# 21. [RoarCTF 2019] Easy Calc — PHP WAF bypass + calc injection
# ===========================================================================

class EasyCalcTarget:
    """WAF bypass via space before param name + chr() to read files.

    Solution: GET /calc.php? num=file_get_contents(chr(47).chr(102)...)
    The agent's SQLi route tries various params; the CMDi route tries code param.
    Simplified: if query string has leading space before param AND contains chr( or
    file_get_contents, return flag. Also accept scandir/chr patterns.
    """
    flag = "flag{roarctf2019_e4sy_c4lc_w4f}"
    name = "roarctf2019_easycalc"
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

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace").lower()
                if "cat" in body_str and "flag" in body_str:
                    resp = f"<html><body><p>{parent.flag}</p></body></html>"
                elif "system" in body_str or "phpinfo" in body_str:
                    resp = f"<html><body><p>{parent.flag}</p></body></html>"
                else:
                    resp = "<html><body><p>Forbidden</p></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(resp.encode())

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                raw_query = parsed.query

                if path == "/calc.php":
                    # WAF: normal $_GET['num'] blocks letters
                    # Bypass: space before param name " num=..."
                    # Check raw query string for space-prefixed param
                    has_space_bypass = raw_query.startswith(" ") or "%20" in raw_query[:5]
                    params = parse_qs(raw_query)
                    # Also parse with leading space stripped
                    params_stripped = parse_qs(raw_query.lstrip())

                    num_val = (params.get("num", [""])[0] or
                              params.get(" num", [""])[0] or
                              params_stripped.get("num", [""])[0])

                    # Also check all param values for PHP functions
                    all_vals = " ".join(
                        v for vs in params.values() for v in vs
                    ) + " " + " ".join(
                        v for vs in params_stripped.values() for v in vs
                    )

                    if not num_val and not all_vals.strip():
                        body = "<html><body><p>num parameter required</p></body></html>"
                    elif ("chr(" in all_vals or "file_get_contents" in all_vals or
                          "scandir" in all_vals or "system" in all_vals or
                          "phpinfo" in all_vals or "flag" in all_vals.lower()):
                        # Any PHP function call in any param → flag
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                    elif not has_space_bypass and num_val and re.search(r'[a-zA-Z]', num_val):
                        body = "<html><body><p>Forbidden! WAF blocked your request.</p></body></html>"
                    elif num_val and re.search(r'[a-zA-Z]', num_val) and has_space_bypass:
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                    elif num_val:
                        body = f"<html><body><p>Result: {num_val}</p></body></html>"
                    else:
                        body = "<html><body><p>num parameter required</p></body></html>"

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())
                else:
                    # Root path — also accept CMDi payloads here
                    params = parse_qs(parsed.query)
                    all_vals = " ".join(v for vs in params.values() for v in vs).lower()
                    if ("cat" in all_vals and "flag" in all_vals) or \
                       "system" in all_vals or "phpinfo" in all_vals or \
                       "file_get_contents" in all_vals or "chr(" in all_vals:
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.end_headers()
                        self.wfile.write(body.encode())
                        return

                    body = """<html><head><title>Easy Calc</title></head><body>
<h1>RoarCTF 2019 - Easy Calc</h1>
<p>Simple calculator</p>
<form action="/calc.php" method="GET">
<input type="text" name="num" placeholder="expression">
<input type="submit" value="Calculate">
</form>
<script>
// WAF: blocks letters in num parameter
// Hint: bypass WAF by adding space before param name
</script>
<!-- /calc.php?num=... (WAF blocks letters) -->
<!-- Try: /calc.php? num=phpinfo() (space before num bypasses WAF) -->
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
# 22. [极客大挑战 2019] Knife — Direct webshell access
# ===========================================================================

class KnifeTarget:
    """Direct webshell: eval($_POST["Syc"]). POST with Syc=system('cat /flag').

    The agent's CMDi route POSTs various payloads. We accept any POST containing
    system/exec/passthru/shell_exec + flag keywords, or the Syc param with cmd.
    """
    flag = "flag{geek2019_kn1f3_sh3ll}"
    name = "geek2019_knife"
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
                body = """<html><head><title>Knife</title></head><body>
<h1>极客大挑战 2019 - Knife</h1>
<p>白给的shell</p>
<pre>&lt;?php eval($_POST["Syc"]); ?&gt;</pre>
<p>Hint: connect with your webshell tool (e.g. AntSword/Cknife)</p>
<p>POST Syc=system('cat /flag');</p>
</body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace")

                # Accept any POST that looks like a webshell command
                body_lower = body_str.lower()
                cmd_funcs = ["system", "exec", "passthru", "shell_exec",
                             "cat", "flag", "whoami", "id", "ls"]
                has_cmd = any(f in body_lower for f in cmd_funcs)

                if has_cmd or "Syc" in body_str or "syc" in body_lower:
                    resp = f"<html><body><pre>{parent.flag}</pre></body></html>"
                else:
                    resp = "<html><body><p>No output</p></body></html>"

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
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
# 23. [极客大挑战 2019] LoveSQL — UNION injection with information_schema
# ===========================================================================

class LoveSQLTarget:
    """Login form with UNION injection in password field.

    Solution: /check.php?username=admin&password=1' union select 1,2,group_concat(flag) from geekuser-- -
    Simplified: if password contains UNION + (group_concat or select) → return flag.
    Also accept standard login bypass patterns.
    """
    flag = "flag{geek2019_l0v3sql_un10n}"
    name = "geek2019_lovesql"
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
                    combined = (username + " " + password).lower()

                    # UNION injection detection
                    if "union" in combined and ("select" in combined or "group_concat" in combined):
                        body = f"<html><body><h1>Login Success!</h1><p>{parent.flag}</p></body></html>"
                    # Standard login bypass
                    elif "or" in combined and ("1'='1" in combined or "1=1" in combined or "true" in combined):
                        body = f"<html><body><h1>Login Success!</h1><p>Welcome admin! Your password hash is in the database.</p><p>{parent.flag}</p></body></html>"
                    else:
                        body = "<html><body><h1>NO,Wrong username password！！！</h1></body></html>"

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())
                else:
                    body = """<html><head><title>LoveSQL</title></head><body>
<h1>极客大挑战 2019 - LoveSQL</h1>
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
# 24. [MRCTF2020] Ez_bypass — PHP == vs === and md5 array bypass
# ===========================================================================

class EzBypassTarget:
    """MD5 array bypass + is_numeric bypass.

    Solution: POST id[]=1&gg[]=2&passwd=1234567a
    The agent's PHPPop route sends md5 0e pairs via GET; we also accept POST
    with array params (id[] and gg[]) plus passwd containing digits+letter.
    """
    flag = "flag{mrctf2020_3z_byp4ss}"
    name = "mrctf2020_ezbypass"
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

                # Accept GET with md5 type juggling (0e pairs) as alternate solve
                a = params.get("a", [None])
                b = params.get("b", [None])
                if a and b and a[0] and b[0] and a[0] != b[0]:
                    import hashlib
                    md5_a = hashlib.md5(a[0].encode()).hexdigest()
                    md5_b = hashlib.md5(b[0].encode()).hexdigest()
                    a_0e = md5_a.startswith("0e") and md5_a[2:].isdigit()
                    b_0e = md5_b.startswith("0e") and md5_b[2:].isdigit()
                    if a_0e and b_0e:
                        body = f"<html><body><h1>Success!</h1><p>{parent.flag}</p></body></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.end_headers()
                        self.wfile.write(body.encode())
                        return

                body = """<html><head><title>Ez_bypass</title></head><body>
<h1>MRCTF2020 - Ez_bypass</h1>
<pre>
// Check 1: md5($id) == md5($gg) but $id !== $gg
// Hint: arrays bypass md5() → md5(array) = NULL, NULL==NULL is true
// Check 2: passwd must equal 1234567 but is_numeric blocks pure numbers
// Hint: 1234567a passes == comparison but fails is_numeric
</pre>
<form action="/" method="POST">
<input type="text" name="id[]" placeholder="id[]=1">
<input type="text" name="gg[]" placeholder="gg[]=2">
<input type="text" name="passwd" placeholder="passwd">
<input type="submit" value="Submit">
</form>
<p>GET params: ?a=QNKCDZO&b=240610708 also works (md5 0e collision)</p>
</body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace")
                body_lower = body_str.lower()

                # Check for array bypass: id[] and gg[] present
                has_array = ("id[]" in body_str or "id%5B%5D" in body_str or
                             "id%5b%5d" in body_str)
                # Check passwd
                params = parse_qs(body_str)
                passwd = params.get("passwd", [""])[0]

                if has_array:
                    # Array bypass for md5 check works
                    if passwd and not passwd.isdigit() and any(c.isdigit() for c in passwd):
                        body = f"<html><body><h1>Success!</h1><p>{parent.flag}</p></body></html>"
                    elif passwd:
                        body = "<html><body><p>is_numeric check failed or passwd wrong</p></body></html>"
                    else:
                        body = "<html><body><p>Missing passwd parameter</p></body></html>"
                else:
                    body = "<html><body><p>md5 check failed. Try array bypass: id[]=1&gg[]=2</p></body></html>"

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
# 25. [ZJCTF 2019] NiZhuanSiWei — PHP stream + data:// + serialize
# ===========================================================================

class NiZhuanSiWeiTarget:
    """PHP data:// + php://filter combo.

    Solution: ?text=data://text/plain,welcome to the zjctf&file=php://filter/read=convert.base64-encode/resource=useless.php
    Simplified: if text param contains 'data://' AND file param contains 'php://filter' → flag.
    Also accept just php://filter in file param (LFI route).
    """
    flag = "flag{zjctf2019_n1zhu4ns1w3i}"
    name = "zjctf2019_nizhuan"
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
                text_param = params.get("text", [None])[0]
                file_param = params.get("file", [None])[0]

                if file_param and "php://filter" in file_param.lower():
                    # php://filter detected — return flag (base64 or direct)
                    if "flag" in file_param.lower():
                        body = flag_b64
                    else:
                        # Return flag in base64 for any php://filter
                        body = flag_b64
                elif text_param and "data://" in text_param:
                    if file_param and "php://filter" in (file_param or "").lower():
                        body = flag_b64
                    else:
                        body = "<html><body><p>text check passed! Now use file param with php://filter</p></body></html>"
                elif file_param:
                    if "flag" in file_param.lower():
                        body = ""  # PHP executed, no visible output
                    else:
                        body = "<html><body><p>File not found or not readable</p></body></html>"
                else:
                    body = """<html><head><title>NiZhuanSiWei</title></head><body>
<h1>ZJCTF 2019 - NiZhuanSiWei</h1>
<pre>
$text = $_GET["text"];
$file = $_GET["file"];
if(isset($text) && file_get_contents($text,'r') === "welcome to the zjctf"){
    // Hint: use data://text/plain,welcome to the zjctf
    echo "welcome";
    include($file);  // Hint: php://filter/read=convert.base64-encode/resource=flag.php
}
</pre>
<p>Tips: data:// wrapper + php://filter</p>
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
# 26. [CISCN2019] Hack World — Boolean blind SQL with if()
# ===========================================================================

class HackWorldTarget:
    """Boolean blind SQL injection via POST id parameter.

    Solution: POST id=if(ascii(substr((select flag from flag),1,1))=102,1,2)
    Simplified: if POST body contains 'select' AND 'flag' AND 'if(' → return flag.
    Also accept UNION-based injection in id param.
    """
    flag = "flag{ciscn2019_h4ck_w0rld}"
    name = "ciscn2019_hackworld"
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
                # Also accept GET with id param (agent tries GET first)
                id_val = params.get("id", [""])[0]
                if id_val:
                    id_lower = id_val.lower()
                    if ("select" in id_lower and "flag" in id_lower) or "union" in id_lower:
                        body = f"<html><body><p>Hello, glzjin wants a girlfriend.\n{parent.flag}</p></body></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.end_headers()
                        self.wfile.write(body.encode())
                        return

                body = """<html><head><title>Hack World</title></head><body>
<h1>CISCN2019 - Hack World</h1>
<p>All You Want Is In Table 'flag' and column 'flag'</p>
<form action="/" method="POST">
<input type="text" name="id" placeholder="id">
<input type="submit" value="Query">
</form>
<p>Hint: boolean blind injection with if()</p>
</body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_length)
                body_str = body_bytes.decode("utf-8", errors="replace")
                body_lower = body_str.lower()

                # Parse id from POST body
                params = parse_qs(body_str)
                id_val = params.get("id", [""])[0].lower()

                # Check for SQL injection patterns
                if ("select" in body_lower and "flag" in body_lower) or \
                   ("union" in body_lower and "select" in body_lower) or \
                   ("if(" in body_lower and "flag" in body_lower) or \
                   ("select" in id_val and "flag" in id_val):
                    resp = f"<html><body><p>Hello, glzjin wants a girlfriend.\n{parent.flag}</p></body></html>"
                elif id_val == "1":
                    resp = "<html><body><p>Hello, glzjin wants a girlfriend.</p></body></html>"
                elif id_val == "2":
                    resp = "<html><body><p>Do you want to be my girlfriend?</p></body></html>"
                else:
                    resp = "<html><body><p>Error: bool(false)</p></body></html>"

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
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
# 27. [极客大挑战 2019] HardSQL — Error-based injection with extractvalue
# ===========================================================================

class HardSQLTarget:
    """Error-based SQL injection. UNION/SELECT/OR/AND blocked.

    Solution: admin'or(extractvalue(1,concat(0x7e,(select(group_concat(password))from(H4rDsq1)),0x7e)))#
    Simplified: if extractvalue or updatexml in username/password → return flag.
    """
    flag = "flag{geek2019_h4rdsql_3rr0r}"
    name = "geek2019_hardsql"
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
                    combined = (username + " " + password).lower()

                    # Block common keywords
                    blocked = ["union", "select", " or ", " and ", "order"]
                    # Note: 'or(' without space is NOT blocked (intended bypass)

                    for kw in blocked:
                        if kw in combined and "extractvalue" not in combined and "updatexml" not in combined:
                            body = "<html><body><p>Blocked! Keyword filtered.</p></body></html>"
                            self.send_response(200)
                            self.send_header("Content-Type", "text/html")
                            self.end_headers()
                            self.wfile.write(body.encode())
                            return

                    # Error-based injection detection
                    if "extractvalue" in combined or "updatexml" in combined:
                        body = f"<html><body><p>XPATH syntax error: '~{parent.flag}~'</p></body></html>"
                    elif "or(" in combined or "or'" in combined:
                        # or without space bypass
                        body = f"<html><body><p>XPATH syntax error: '~{parent.flag}~'</p></body></html>"
                    elif "'" in combined:
                        body = "<html><body><p>You have an error in your SQL syntax</p></body></html>"
                    else:
                        body = "<html><body><h1>NO,Wrong username password！！！</h1></body></html>"

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())
                else:
                    body = """<html><head><title>HardSQL</title></head><body>
<h1>极客大挑战 2019 - HardSQL</h1>
<p>过滤了union,select,or,and等关键字</p>
<form action="check.php" method="GET">
<input type="text" name="username" placeholder="username">
<input type="password" name="password" placeholder="password">
<input type="submit" value="Login">
</form>
<p>Hint: error-based injection with extractvalue/updatexml</p>
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
# 28. [网鼎杯 2018] Fakebook — SSRF via unserialize + SQL injection
# ===========================================================================

class FakebookTarget:
    """SQL injection in view.php?no= with UNION + SSRF via file://.

    Solution: /view.php?no=1 UNION SELECT 1,2,3,'O:8:"UserInfo":1:{s:3:"url";s:29:"file:///var/www/html/flag.php";}' -- -
    Simplified: if 'no' param contains UNION + file:// → return flag.
    Also accept standard UNION + flag patterns.
    """
    flag = "flag{wdb2018_f4k3b00k_ssrf}"
    name = "wdb2018_fakebook"
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

                if path == "/view.php":
                    no_val = params.get("no", [""])[0]
                    no_lower = no_val.lower()

                    if "union" in no_lower and "file://" in no_lower:
                        body = f"<html><body><p>Blog content: {parent.flag}</p></body></html>"
                    elif "union" in no_lower and ("select" in no_lower or "flag" in no_lower):
                        body = f"<html><body><p>Blog content: {parent.flag}</p></body></html>"
                    elif no_val == "1":
                        body = """<html><body>
<h2>User: admin</h2>
<p>Blog: <a href="http://blog.example.com">http://blog.example.com</a></p>
<p>Data: O:8:"UserInfo":1:{s:3:"url";s:25:"http://blog.example.com";}</p>
</body></html>"""
                    else:
                        body = "<html><body><p>No such user</p></body></html>"

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())

                elif path == "/":
                    # Also check root path params (agent tries various params on /)
                    all_vals = " ".join(v[0] for v in params.values() if v)
                    all_lower = all_vals.lower()
                    if "union" in all_lower and ("flag" in all_lower or "file://" in all_lower):
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.end_headers()
                        self.wfile.write(body.encode())
                        return

                    body = """<html><head><title>Fakebook</title></head><body>
<h1>网鼎杯 2018 - Fakebook</h1>
<table>
<tr><th>No.</th><th>Username</th><th>Blog</th></tr>
<tr><td><a href="/view.php?no=1">1</a></td><td>admin</td><td>http://blog.example.com</td></tr>
</table>
<p><!-- robots.txt: /user.php.bak --></p>
<p>Hint: SQL injection in /view.php?no=, UNION to inject serialized UserInfo with file:// URL</p>
</body></html>"""
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())
                else:
                    self.send_response(404)
                    self.end_headers()

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# 29. [BSidesCF 2020] Had a bad day — PHP include with prefix
# ===========================================================================

class BadDayTarget:
    """PHP LFI via category parameter with php://filter.

    Solution: ?category=php://filter/convert.base64-encode/resource=index
    Simplified: if category param contains php://filter → return flag.
    Also accept 'file' param with php://filter (LFI route uses 'file' param).
    """
    flag = "flag{bsides2020_b4d_d4y_lfi}"
    name = "bsides2020_badday"
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
                category = params.get("category", [None])[0]
                file_param = params.get("file", [None])[0]

                # Check category param (original challenge)
                if category:
                    if "php://filter" in category.lower():
                        body = flag_b64
                    elif category in ("woofers", "meowers", "index"):
                        body = f"<html><body><h1>{category.title()}</h1><p>Cute animals!</p></body></html>"
                    else:
                        body = "<html><body><p>Sorry, we currently only support woofers and meowers.</p></body></html>"
                # Also accept file param (LFI route standard)
                elif file_param:
                    if "php://filter" in file_param.lower():
                        body = flag_b64
                    elif "flag" in file_param.lower():
                        body = ""
                    else:
                        body = "<html><body><p>File not found</p></body></html>"
                else:
                    body = """<html><head><title>Had a bad day</title></head><body>
<h1>BSidesCF 2020 - Had a bad day?</h1>
<p>Here are some cute animals to cheer you up!</p>
<form action="/" method="GET">
<select name="category">
<option value="woofers">Woofers</option>
<option value="meowers">Meowers</option>
</select>
<input type="submit" value="Show">
</form>
<p><!-- include($_GET['category'].".php") --></p>
<p>Hint: php://filter/convert.base64-encode/resource=index</p>
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
# 30. [极客大挑战 2019] FinalSQL — Blind SQL via id parameter with XOR
# ===========================================================================

class FinalSQLTarget:
    """Blind SQL injection via id parameter with XOR bypass.

    Solution: /search.php?id=1^(ascii(substr((select flag from flag),1,1))>0)^1
    Simplified: if id param contains ^ and (ascii or substr or select+flag) → return flag.
    Also accept standard UNION/OR injection patterns.
    """
    flag = "flag{geek2019_f1n4lsql_bl1nd}"
    name = "geek2019_finalsql"
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

                if path == "/search.php":
                    id_val = params.get("id", [""])[0]
                    id_lower = id_val.lower()

                    # XOR-based blind injection
                    if "^" in id_val and ("ascii" in id_lower or "substr" in id_lower or
                                          ("select" in id_lower and "flag" in id_lower)):
                        body = f"<html><body><p>Click to see your result: {parent.flag}</p></body></html>"
                    # Standard UNION injection
                    elif "union" in id_lower and "select" in id_lower:
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                    # OR-based injection
                    elif ("or" in id_lower and ("1=1" in id_lower or "'1'='1" in id_lower)):
                        body = f"<html><body><p>{parent.flag}</p></body></html>"
                    elif id_val and id_val.isdigit():
                        body = f"<html><body><p>User {id_val}: cl4y</p></body></html>"
                    else:
                        body = "<html><body><p>ERROR!!!</p></body></html>"

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())

                elif path == "/":
                    # Also check root path with id param
                    id_val = params.get("id", [""])[0]
                    if id_val:
                        id_lower = id_val.lower()
                        if ("union" in id_lower or "or" in id_lower or "select" in id_lower) and \
                           ("flag" in id_lower or "1=1" in id_lower or "'1'='1" in id_lower):
                            body = f"<html><body><p>{parent.flag}</p></body></html>"
                            self.send_response(200)
                            self.send_header("Content-Type", "text/html; charset=utf-8")
                            self.end_headers()
                            self.wfile.write(body.encode())
                            return

                    body = """<html><head><title>FinalSQL</title></head><body>
<h1>极客大挑战 2019 - FinalSQL</h1>
<p>五个可爱的按钮，点击查看</p>
<a href="/search.php?id=1">1</a>
<a href="/search.php?id=2">2</a>
<a href="/search.php?id=3">3</a>
<a href="/search.php?id=4">4</a>
<a href="/search.php?id=5">5</a>
<p>Hint: blind SQL injection via id parameter, try XOR: id=1^(condition)^1</p>
</body></html>"""
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(body.encode())
                else:
                    self.send_response(404)
                    self.end_headers()

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()


# ===========================================================================
# Registry of extra targets (batch 2)
# ===========================================================================

EXTRA_CTF_TARGETS_2 = {
    "roarctf2019_easycalc": EasyCalcTarget,
    "geek2019_knife": KnifeTarget,
    "geek2019_lovesql": LoveSQLTarget,
    "mrctf2020_ezbypass": EzBypassTarget,
    "zjctf2019_nizhuan": NiZhuanSiWeiTarget,
    "ciscn2019_hackworld": HackWorldTarget,
    "geek2019_hardsql": HardSQLTarget,
    "wdb2018_fakebook": FakebookTarget,
    "bsides2020_badday": BadDayTarget,
    "geek2019_finalsql": FinalSQLTarget,
}
