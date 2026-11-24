import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import lab_app
import idor_tester as it


@pytest.fixture(scope="module")
def base():
    srv = lab_app.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def test_parse_ids():
    assert it.parse_ids("1-3,7") == [1, 2, 3, 7]


def test_owner_of():
    assert it.owner_of('{"owner": "bob"}') == "bob"
    assert it.owner_of("not json") is None


def test_classify():
    assert it.classify(200, '{"owner":"bob"}', "alice") == "idor"
    assert it.classify(200, '{"owner":"alice"}', "alice") == "own"
    assert it.classify(403, "", "alice") == "denied"
    assert it.classify(404, "", "alice") == "missing"


def test_vulnerable_orders(base):
    res = it.scan(base + "/api/orders/{id}", range(101, 105), "alice-token", "alice")
    bad = [r["id"] for r in res if r["verdict"] == "idor"]
    assert bad == [102, 103, 104]


def test_safe_orders_has_no_idor(base):
    res = it.scan(base + "/api/safe-orders/{id}", range(101, 105), "alice-token", "alice")
    assert not [r for r in res if r["verdict"] == "idor"]


def test_profile_idor(base):
    res = it.scan(base + "/api/profile/{id}", range(1, 5), "alice-token", "alice")
    assert len([r for r in res if r["verdict"] == "idor"]) == 3


def test_no_token_denied(base):
    res = it.scan(base + "/api/orders/{id}", [101], "", "alice")
    assert res[0]["verdict"] == "denied"
