#!/usr/bin/env python3
"""Small vulnerable lab app for practicing IDOR. Listens on 127.0.0.1 only.
Token is sent as 'Authorization: Bearer <name>-token'."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

USERS = {1: "alice", 2: "bob", 3: "carol", 4: "dave"}
ORDERS = {
    101: {"owner": "alice", "item": "Keyboard", "address": "12 Park St"},
    102: {"owner": "bob", "item": "Monitor", "address": "7 Lake Rd"},
    103: {"owner": "carol", "item": "Laptop", "address": "99 Hill Ave"},
    104: {"owner": "dave", "item": "Mouse", "address": "3 Fort Rd"},
}


def user_from_token(header):
    if header and header.startswith("Bearer ") and header.endswith("-token"):
        name = header[7:-6]
        if name in USERS.values():
            return name
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        me = user_from_token(self.headers.get("Authorization"))
        if not me:
            return self.send(401, {"error": "login required"})
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[2].isdigit():
            n = int(parts[2])
            if parts[1] == "orders":
                # vulnerable: never checks the owner
                if n in ORDERS:
                    return self.send(200, ORDERS[n])
                return self.send(404, {"error": "not found"})
            if parts[1] == "safe-orders":
                o = ORDERS.get(n)
                if not o or o["owner"] != me:
                    return self.send(404, {"error": "not found"})
                return self.send(200, o)
            if parts[1] == "profile":
                # vulnerable: any logged in user can read any profile
                if n in USERS:
                    return self.send(200, {"id": n, "name": USERS[n],
                                           "email": USERS[n] + "@example.test", "owner": USERS[n]})
                return self.send(404, {"error": "not found"})
        self.send(404, {"error": "not found"})


def make_server(port):
    return HTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print("lab app on http://127.0.0.1:%d" % port)
    make_server(port).serve_forever()
