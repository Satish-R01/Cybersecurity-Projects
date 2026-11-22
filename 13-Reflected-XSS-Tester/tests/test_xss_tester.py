import os
import sys
import threading
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
import xss_tester as x
import lab_app


@pytest.fixture(scope="module")
def base():
    srv = HTTPServer(("127.0.0.1", 0), lab_app.Lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def bad(res):
    return {r["payload"] for r in res if r["status"] == "UNENCODED"}


def test_search_is_vulnerable(base):
    res = x.test_url(base + "/search?q=a", "q")
    assert "script tag" in bad(res)
    assert "img onerror" in bad(res)


def test_safe_page_is_clean(base):
    assert bad(x.test_url(base + "/safe?q=a", "q")) == set()


def test_weak_filter_bypassed_by_nested(base):
    b = bad(x.test_url(base + "/greet?name=a", "name"))
    assert "nested script" in b
    assert "script tag" not in b


def test_attribute_context(base):
    res = x.test_url(base + "/attr?v=a", "v")
    r = [r for r in res if r["payload"] == "attribute break"][0]
    assert r["status"] == "UNENCODED"
    assert r["context"] == "attribute"


def test_get_context():
    assert x.get_context("<p>m1</p>", "m1") == "html"
    assert x.get_context("<script>var a='m1'</script>", "m1") == "script"
    assert x.get_context("<p>none</p>", "m1") == "none"


def test_set_param_replaces():
    assert x.set_param("http://h/a?q=1&z=2", "q", "<b>") == "http://h/a?z=2&q=%3Cb%3E"


def test_permission_check():
    assert x.is_allowed("http://127.0.0.1:1/", False)
    assert not x.is_allowed("http://example.com/", False)
    assert x.is_allowed("http://example.com/", True)


def test_main_exit_code(base, capsys):
    assert x.main([base + "/search?q=a"]) == 1
    assert x.main([base + "/safe?q=a"]) == 0
