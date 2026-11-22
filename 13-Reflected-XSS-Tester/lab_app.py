"""Tiny vulnerable lab app for practicing reflected XSS testing.
It only listens on 127.0.0.1. Do not expose it to a network."""
import html
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def page(self, body):
        data = ("<html><body>" + body + "</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/search":
            # vulnerable: input goes into the page as it is
            self.page("<h1>Results for " + q.get("q", [""])[0] + "</h1>")
        elif u.path == "/greet":
            # weak filter: removes the word script only once, case sensitive
            name = q.get("name", [""])[0].replace("script", "")
            self.page("<p>Hello " + name + "</p>")
        elif u.path == "/attr":
            # vulnerable: input goes inside a quoted attribute
            self.page('<input type="text" value="' + q.get("v", [""])[0] + '">')
        elif u.path == "/safe":
            # safe: output is HTML encoded
            self.page("<h1>Results for " + html.escape(q.get("q", [""])[0]) + "</h1>")
        else:
            self.page("<p>lab app</p>")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    HTTPServer(("127.0.0.1", port), Lab).serve_forever()
