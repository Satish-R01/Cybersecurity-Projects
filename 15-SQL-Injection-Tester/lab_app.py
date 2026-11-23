"""Tiny vulnerable lab app for practicing SQL injection testing.
It uses an in-memory SQLite database and only listens on 127.0.0.1.
Do not expose it to a network."""
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


def make_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE products (id INTEGER, name TEXT, price REAL)")
    db.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    db.executemany("INSERT INTO products VALUES (?,?,?)",
                   [(1, "keyboard", 25.0), (2, "mouse", 10.0), (3, "monitor", 120.0)])
    db.execute("INSERT INTO users VALUES (1, 'admin', 'not-a-real-password')")
    return db


DB = make_db()


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/product":
            # vulnerable: id goes straight into the query, errors are shown
            pid = q.get("id", ["1"])[0]
            try:
                rows = DB.execute("SELECT name, price FROM products WHERE id = " + pid).fetchall()
            except sqlite3.Error as e:
                return self.reply(500, "Database error: " + str(e))
            self.reply(200, "\n".join("%s %s" % r for r in rows) or "no results")
        elif u.path == "/search":
            # vulnerable but quiet: no error text, only different results
            term = q.get("q", [""])[0]
            try:
                rows = DB.execute("SELECT name FROM products WHERE name LIKE '%" + term + "%'").fetchall()
            except sqlite3.Error:
                return self.reply(200, "no results")
            self.reply(200, "\n".join(r[0] for r in rows) or "no results")
        elif u.path == "/safe":
            # safe: parameterized query
            term = q.get("id", ["1"])[0]
            rows = DB.execute("SELECT name, price FROM products WHERE id = ?", (term,)).fetchall()
            self.reply(200, "\n".join("%s %s" % r for r in rows) or "no results")
        else:
            self.reply(200, "lab app")


def make_server(port=8000):
    return HTTPServer(("127.0.0.1", port), Lab)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print("Lab app on http://127.0.0.1:%d" % port)
    make_server(port).serve_forever()
