import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import headers_checker as hc

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "responses.txt")


def codes(headers, https=True):
    return {f["code"] for f in hc.analyze(headers, https)}


def load():
    with open(SAMPLE) as f:
        return hc.split_responses(f.read())


def test_parse_response():
    status, h = hc.parse_response("HTTP/1.1 404 Not Found\nServer: x\nSet-Cookie: a=1\nSet-Cookie: b=2\n\nbody")
    assert status == 404
    assert h["server"] == "x"
    assert h["set-cookie"] == ["a=1", "b=2"]


def test_missing_everything():
    c = codes({})
    assert {"hsts_missing", "csp_missing", "clickjacking", "nosniff_missing", "referrer_missing"} <= c


def test_hsts_skipped_on_http():
    assert "hsts_missing" not in codes({}, https=False)


def test_csp_unsafe():
    c = codes({"content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"})
    assert "csp_unsafe_inline" in c and "csp_unsafe_eval" in c


def test_frame_ancestors_covers_clickjacking():
    assert "clickjacking" not in codes({"content-security-policy": "default-src 'self'; frame-ancestors 'none'"})


def test_xfo_invalid():
    assert "xfo_invalid" in codes({"x-frame-options": "ALLOWALL"})


def test_cors_wildcard_creds():
    h = {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
    assert "cors_wildcard_creds" in codes(h)


def test_cookie_flags():
    c = codes({"set-cookie": "PHPSESSID=1; path=/"})
    assert {"cookie_no_secure", "cookie_no_httponly", "cookie_no_samesite"} <= c


def test_version_leak():
    c = codes({"server": "Apache/2.4.29", "x-powered-by": "PHP/7.2"})
    assert "server_version" in c and "leak_x_powered_by" in c


def test_sample_grades():
    results = {}
    for url, raw in load():
        _, h = hc.parse_response(raw)
        results[url] = hc.score(hc.analyze(h))[1]
    assert results["https://shop.example.test/"] == "F"
    assert results["https://secure.example.test/"] == "A"


def test_exit_code(capsys):
    assert hc.main([SAMPLE]) == 1
    assert "shop.example.test" in capsys.readouterr().out
