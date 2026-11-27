"""Small lab app with hidden files and folders. Listens on 127.0.0.1 only.

It has a "soft 404": unknown paths return 200 with a friendly page.
This is on purpose, so the fuzzer has to deal with it.
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGES = {
    "/": (200, "<h1>Lab Shop</h1><a href='/login'>Login</a>"),
    "/login": (200, "<form method='post'><input name='user'><input name='pass'></form>"),
    "/api": (200, '{"service": "lab-shop", "version": "1.2"}'),
    "/assets": (301, ""),                       # redirects to /assets/
    "/admin": (401, "Authentication required"),
    "/uploads": (403, "Forbidden"),
    "/robots.txt": (200, "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n"),
    "/.git/HEAD": (200, "ref: refs/heads/main\n"),
    "/.env": (200, "DB_PASSWORD=labpass123\nSECRET_KEY=abc123\n"),
    "/backup.zip": (200, "PK\x03\x04" + "x" * 400),
    "/config.bak": (200, "db_host=10.0.0.5\ndb_user=root\ndb_pass=toor\n"),
    "/phpinfo": (200, "<title>phpinfo()</title>" + "PHP Version 7.4.3 " * 20),
    "/server-status": (403, "Forbidden"),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in PAGES:
            code, body = PAGES[path]
        else:
            # soft 404: the page says not found but the status is 200
            code = 200
            body = "<h1>Sorry</h1><p>We could not find %s here. Try the home page.</p>" % path
        data = body.encode("latin-1", "replace")
        self.send_response(code)
        if code == 301:
            self.send_header("Location", path + "/")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_server(port=8000):
    return HTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print("Lab app on http://127.0.0.1:%d" % port)
    make_server(port).serve_forever()
