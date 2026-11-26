import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import lab_app
import rate_limit_tester as rt


@pytest.fixture()
def base():
    srv = lab_app.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def pw(n):
    return ["wrong%d" % i for i in range(n)]


def test_classify_429():
    assert rt.classify(429, "", {}) == "blocked"


def test_classify_retry_after():
    assert rt.classify(403, "", {"Retry-After": "10"}) == "blocked"


def test_classify_lock_text():
    assert rt.classify(401, "Account locked", {}) == "blocked"


def test_classify_normal_401():
    assert rt.classify(401, '{"ok": false}', {}) == "allowed"


def test_load_passwords_repeats(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("# c\na\nb\n")
    assert rt.load_passwords(str(f), 5) == ["a", "b", "a", "b", "a"]


def test_vulnerable_endpoint(base):
    rep = rt.run(base + "/vuln/login", "alice", pw(12))
    assert rep["vulnerable"] is True
    assert rep["first_block"] is None


def test_safe_endpoint_blocks(base):
    rep = rt.run(base + "/safe/login", "alice", pw(12))
    assert rep["vulnerable"] is False
    assert rep["first_block"] == 6
    assert rep["results"][5]["retry_after"] is not None


def test_remote_refused():
    with pytest.raises(SystemExit):
        rt.check_target("http://example.com/login", False)


def test_main_exit_codes(base, capsys):
    assert rt.main([base + "/vuln/login", "--user", "alice", "--passwords",
                    os.path.join(os.path.dirname(__file__), "..", "samples", "passwords.txt")]) == 1
    assert rt.main([base + "/safe/login", "--user", "bob", "--passwords",
                    os.path.join(os.path.dirname(__file__), "..", "samples", "passwords.txt")]) == 0
