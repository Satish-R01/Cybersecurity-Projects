"""Tiny vulnerable lab app for practicing open redirect testing.
It only listens on 127.0.0.1. Do not expose it to a network."""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/login":
            # vulnerable: redirects to whatever "next" says
            self.redirect(q.get("next", ["/"])[0])
        elif u.path == "/go":
            # weak check: only looks at the start of the string
            url = q.get("url", ["/"])[0]
            if url.startswith("http://localhost") or url.startswith("/"):
                self.redirect(url)
            else:
                self.send_response(400)
                self.end_headers()
        elif u.path == "/safe":
            # safe: only local paths
            n = q.get("next", ["/"])[0]
            if n.startswith("/") and not n.startswith("//") and "\\" not in n:
                self.redirect(n)
            else:
                self.redirect("/")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"lab app")


def make_server(port=0):
    return HTTPServer(("127.0.0.1", port), Lab)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print("Lab app on http://127.0.0.1:%d" % port)
    make_server(port).serve_forever()
