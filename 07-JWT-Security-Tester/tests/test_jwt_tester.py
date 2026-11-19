import base64
import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import jwt_tester

ROOT = os.path.join(os.path.dirname(__file__), "..")
SECRETS = os.path.join(ROOT, "samples", "secrets.txt")


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make(header, payload, secret=None):
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    p = b64(json.dumps(payload, separators=(",", ":")).encode())
    if secret is None:
        return h + "." + p + "."
    sig = hmac.new(secret.encode(), (h + "." + p).encode(), hashlib.sha256).digest()
    return h + "." + p + "." + b64(sig)


def ids(result):
    return {f["id"] for f in result["findings"]}


def test_split_token_bad():
    try:
        jwt_tester.split_token("only.two")
    except ValueError:
        pass
    else:
        assert False, "should raise on 2 parts"


def test_verify_hs256_true_and_false():
    t = make({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
    assert jwt_tester.verify_hs256(t, "secret") is True
    assert jwt_tester.verify_hs256(t, "wrong") is False


def test_alg_none_flagged():
    t = make({"alg": "none", "typ": "JWT"}, {"sub": "1", "admin": True})
    result = jwt_tester.analyse(t)
    assert "alg_none" in ids(result)
    assert "empty_sig" in ids(result)


def test_no_exp_flagged():
    t = make({"alg": "HS256"}, {"sub": "1"}, "secret")
    result = jwt_tester.analyse(t)
    assert "no_exp" in ids(result)


def test_expired():
    now = 1800000000
    t = make({"alg": "HS256"}, {"sub": "1", "iat": now - 200000, "exp": now - 100000}, "k")
    result = jwt_tester.analyse(t, now=now)
    assert "expired" in ids(result)


def test_long_life():
    now = 1800000000
    t = make({"alg": "HS256"}, {"sub": "1", "iat": now, "exp": now + 200000}, "k")
    result = jwt_tester.analyse(t, now=now)
    assert "long_life" in ids(result)


def test_valid_time():
    now = 1800000000
    t = make({"alg": "HS256"}, {"sub": "1", "iat": now, "exp": now + 600}, "k")
    result = jwt_tester.analyse(t, now=now)
    assert "valid_time" in ids(result)
    assert "expired" not in ids(result)


def test_weak_secret_cracked():
    t = make({"alg": "HS256"}, {"sub": "1"}, "password")
    with open(SECRETS) as fh:
        words = fh.read().splitlines()
    result = jwt_tester.analyse(t, words=words, now=1)
    assert "weak_secret" in ids(result)


def test_strong_secret_not_cracked():
    t = make({"alg": "HS256"}, {"sub": "1"}, "a-very-long-random-secret-7f3b9c2e8d14")
    with open(SECRETS) as fh:
        words = fh.read().splitlines()
    result = jwt_tester.analyse(t, words=words, now=1)
    assert "weak_secret" not in ids(result)
    assert "secret_not_found" in ids(result)


def test_sensitive_claim():
    t = make({"alg": "HS256"}, {"sub": "1", "password": "x"}, "k")
    result = jwt_tester.analyse(t)
    assert "sensitive_claim" in ids(result)


def test_asym_confusion_and_no_kid():
    t = make({"alg": "RS256"}, {"sub": "1"}) + "ZmFrZQ"
    result = jwt_tester.analyse(t)
    assert "alg_confusion" in ids(result)
    assert "no_kid" in ids(result)


def test_forge_alg_none():
    t = make({"alg": "HS256"}, {"sub": "1", "admin": False}, "secret")
    forged = jwt_tester.forge_alg_none(t)
    h, p, s = jwt_tester.split_token(forged)
    assert s == ""
    assert jwt_tester.decode_part(h)["alg"] == "none"


def test_main_returns_nonzero_on_problem(capsys):
    t = make({"alg": "none"}, {"sub": "1"})
    rc = jwt_tester.main([t])
    assert rc == 1
