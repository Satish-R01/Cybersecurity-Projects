import os
import sys
import threading
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import csrf_checker as c
import lab_app

S = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def read(n):
    return open(os.path.join(S, n)).read()


def test_parse_form_without_token():
    forms = c.parse_forms(read("form_no_token.html"))
    assert forms[0]["method"] == "post"
    assert c.find_token_field(forms[0]["fields"]) is None


def test_parse_form_with_token():
    forms = c.parse_forms(read("form_with_token.html"))
    assert c.find_token_field(forms[0]["fields"]) == "authenticity_token"


def test_cookie_flags():
    n, f = c.parse_cookie_flags("sid=1; Path=/; HttpOnly; SameSite=Strict")
    assert n == "sid" and f["httponly"] and f["samesite"] == "strict"
    assert c.parse_cookie_flags("sid=1")[1]["samesite"] is None


def start():
    srv = HTTPServer(("127.0.0.1", 0), lab_app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_vulnerable_form():
    srv, base = start()
    try:
        msgs = [m for _, m in c.check(base + "/vuln/form")]
        assert any("no CSRF token" in m for m in msgs)
        assert any("accepts the POST with no token" in m for m in msgs)
        assert c.main([base + "/vuln/form"]) == 1
    finally:
        srv.shutdown()


def test_weak_static_token():
    srv, base = start()
    try:
        msgs = [m for _, m in c.check(base + "/weak/form")]
        assert any("same for different sessions" in m for m in msgs)
        assert any("short" in m for m in msgs)
    finally:
        srv.shutdown()


def test_safe_form():
    srv, base = start()
    try:
        f = c.check(base + "/safe/form")
        assert not any(s == "HIGH" for s, _ in f)
        assert c.main([base + "/safe/form"]) == 0
    finally:
        srv.shutdown()


def test_refuses_remote():
    assert c.main(["http://example.com/form"]) == 2
