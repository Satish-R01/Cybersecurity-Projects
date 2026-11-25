"""Small vulnerable lab app for practicing CSRF checks. Listens on 127.0.0.1 only."""
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

SESSIONS = {}  # sid -> real csrf token for /safe
STATIC_TOKEN = "12345"  # /weak uses the same token for everybody


def page(action, token_field):
    return ("<html><body><h1>Transfer</h1>"
            f'<form method="POST" action="{action}">'
            '<input name="to" value="bob"><input name="amount" value="10">'
            f"{token_field}</form></body></html>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def sid(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        return ""

    def send(self, code, body, cookie=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/vuln/form":
            self.send(200, page("/vuln/transfer", ""), "sid=abc; Path=/")
        elif self.path == "/weak/form":
            f = f'<input type="hidden" name="csrf_token" value="{STATIC_TOKEN}">'
            self.send(200, page("/weak/transfer", f), "sid=abc; Path=/")
        elif self.path == "/safe/form":
            sid = secrets.token_hex(8)
            SESSIONS[sid] = secrets.token_hex(16)
            f = f'<input type="hidden" name="csrf_token" value="{SESSIONS[sid]}">'
            self.send(200, page("/safe/transfer", f),
                      f"sid={sid}; Path=/; HttpOnly; SameSite=Strict")
        else:
            self.send(404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = parse_qs(self.rfile.read(n).decode())
        token = data.get("csrf_token", [""])[0]
        if self.path == "/vuln/transfer":
            self.send(200, "transfer done")
        elif self.path == "/weak/transfer":
            ok = token == STATIC_TOKEN
            self.send(200 if ok else 403, "transfer done" if ok else "bad token")
        elif self.path == "/safe/transfer":
            ok = bool(token) and SESSIONS.get(self.sid()) == token
            self.send(200 if ok else 403, "transfer done" if ok else "bad token")
        else:
            self.send(404, "not found")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
