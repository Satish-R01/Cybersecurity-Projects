"""Small lab app with two login endpoints. Listens on 127.0.0.1 only."""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {"alice": "S3cret!pass", "bob": "hunter22"}
MAX_FAILS = 5          # the safe endpoint blocks after this many failures
BLOCK_SECONDS = 30


class State:
    fails = {}         # username -> failed count on the safe endpoint
    blocked_until = {}


def reset():
    State.fails = {}
    State.blocked_until = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        user = str(body.get("username", ""))
        pw = str(body.get("password", ""))
        ok = USERS.get(user) == pw
        if self.path == "/vuln/login":
            # no limit at all
            return self._send(200 if ok else 401, {"ok": ok})
        if self.path == "/safe/login":
            now = time.time()
            until = State.blocked_until.get(user, 0)
            if until > now:
                wait = int(until - now) + 1
                return self._send(429, {"error": "too many attempts"},
                                  {"Retry-After": str(wait)})
            if ok:
                State.fails[user] = 0
                return self._send(200, {"ok": True})
            State.fails[user] = State.fails.get(user, 0) + 1
            if State.fails[user] >= MAX_FAILS:
                State.blocked_until[user] = now + BLOCK_SECONDS
            return self._send(401, {"ok": False})
        self._send(404, {"error": "not found"})


def make_server(port=8000):
    reset()
    return HTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print("Lab app on http://127.0.0.1:%d" % port)
    make_server(port).serve_forever()
