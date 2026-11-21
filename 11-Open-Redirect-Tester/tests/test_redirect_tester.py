import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import lab_app
import redirect_tester as rt


@pytest.fixture(scope="module")
def base():
    srv = lab_app.make_server(0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def test_relative_is_not_external():
    assert not rt.is_redirect_to_other_host("/dashboard", "127.0.0.1")


def test_absolute_other_host_is_external():
    assert rt.is_redirect_to_other_host("https://evil.example/", "127.0.0.1")


def test_protocol_relative_and_backslash():
    assert rt.is_redirect_to_other_host("//evil.example/", "127.0.0.1")
    assert rt.is_redirect_to_other_host("/\\evil.example", "127.0.0.1")


def test_same_host_absolute_ok():
    assert not rt.is_redirect_to_other_host("http://127.0.0.1:8000/x", "127.0.0.1")


def test_build_url_replaces_param():
    u = rt.build_url("http://a/x?next=/&b=1", "next", "//e/")
    assert "b=1" in u and "next=//e/" in u


def test_vulnerable_login_found(base):
    f = rt.test_param(base + "/login?next=/", "next")
    assert len(f) >= 5


def test_weak_check_only_prefix_bypass(base):
    f = rt.test_param(base + "/go?url=/", "url")
    names = {x["payload"] for x in f}
    assert "absolute url" not in names
    assert "protocol relative" in names


def test_safe_endpoint_clean(base):
    assert rt.test_param(base + "/safe?next=/", "next") == []


def test_main_exit_codes(base, capsys):
    assert rt.main([base + "/login?next=/"]) == 1
    assert rt.main([base + "/safe?next=/"]) == 0


def test_remote_host_skipped(capsys):
    assert rt.main(["http://example.com/?next=/"]) == 0
    assert "Skipping" in capsys.readouterr().err
