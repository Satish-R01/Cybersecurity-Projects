import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import lab_app
import sqli_tester as st


@pytest.fixture(scope="module")
def base():
    srv = lab_app.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def test_sample_errors_detected():
    path = os.path.join(os.path.dirname(__file__), "..", "samples", "error_responses.txt")
    lines = open(path).read().splitlines()
    names = [st.find_db_error(l) for l in lines]
    assert names == ["SQLite", "MySQL", "PostgreSQL", "MSSQL", "Oracle", None]


def test_same_page():
    assert st.same_page("a b", "a b")
    assert not st.same_page("a b c d", "no results")


def test_build_url_replaces_param():
    u = st.build_url("http://x/p?id=1&a=2", "id", "1'")
    assert "id=1%27" in u and "a=2" in u and u.count("id=") == 1


def test_error_based_found(base):
    f = st.test_param(base + "/product?id=1", "id")
    assert any(x["type"] == "error-based" for x in f)


def test_boolean_found_on_quiet_page(base):
    f = st.test_param(base + "/search?q=mouse", "q")
    assert any(x["type"] == "boolean-based" for x in f)


def test_safe_page_has_no_findings(base):
    assert st.test_param(base + "/safe?id=1", "id") == []


def test_refuses_remote_host(capsys):
    sys.argv = ["x", "http://example.com/p?id=1"]
    assert st.main() == 2
    assert "Refusing" in capsys.readouterr().out
