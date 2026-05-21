"""Simple vulnerable HTTP server for testing AutoPenX capabilities.
Run: python test_target.py
Exposes: http://127.0.0.1:8888
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<html>
<head><title>Login</title></head>
<body>
<h1>Login Page</h1>
<form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username" />
    <input type="password" name="password" placeholder="Password" />
    <input type="submit" value="Login" />
</form>
</body>
</html>""")

        elif parsed.path == "/search":
            query = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Search results for: {query}</body></html>".encode())

        elif parsed.path == "/profile":
            uid = params.get("id", ["1"])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>User Profile ID: {uid}</body></html>".encode())

        elif parsed.path == "/status":
            cmd = params.get("cmd", ["status"])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Status check: {cmd}</body></html>".encode())

        elif parsed.path == "/redirect":
            url = params.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()

        elif parsed.path == "/upload":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<html>
<body>
<h1>File Upload</h1>
<form method="POST" action="/upload" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="submit" value="Upload" />
</form>
</body>
</html>""")

        elif parsed.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Admin Panel</h1></body></html>")

        elif parsed.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /backup/\nDisallow: /.git/\n")

        elif parsed.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecret123\nAPI_KEY=sk-test-key-12345\n")

        elif parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<html>
<head><title>Vulnerable Test App</title></head>
<body>
<h1>Welcome to Test App</h1>
<ul>
<li><a href="/login">Login</a></li>
<li><a href="/search?q=test">Search</a></li>
<li><a href="/profile?id=1">Profile</a></li>
<li><a href="/status?cmd=status">Status</a></li>
<li><a href="/upload">Upload</a></li>
</ul>
</body>
</html>""")

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>404 Not Found</body></html>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if self.path == "/login":
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "session=test123")
            self.end_headers()

        elif self.path == "/upload":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>File uploaded successfully!</body></html>")

        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')

    def log_message(self, format, *args):
        pass  # Suppress access logs

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8888), VulnerableHandler)
    print("Vulnerable test target running on http://127.0.0.1:8888")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
