#!/usr/bin/env python3
"""Reflected XSS tester. Sends a unique marker with payloads to a URL
parameter and checks how the value comes back in the HTML.
Only test targets you own or have permission to test."""
import argparse
import json
import sys
import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from urllib.request import build_opener, ProxyHandler, Request
from urllib.error import HTTPError

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

# (name, template, what must come back unencoded to be exploitable)
PAYLOADS = [
    ("script tag", "<script>{m}</script>", "<script>"),
    ("img onerror", "<img src=x onerror={m}>", "<img "),
    ("svg onload", "<svg onload={m}>", "<svg "),
    ("attribute break", '"><b>{m}</b>', '"><b>'),
    ("event handler", '" autofocus onfocus={m} x="', '" autofocus'),
    ("mixed case script", "<ScRiPt>{m}</ScRiPt>", "<ScRiPt>"),
    ("nested script", "<scrscriptipt>{m}</scrscriptipt>", "<script>"),
]


def make_marker():
    return "xss" + uuid.uuid4().hex[:8]


def set_param(url, param, value):
    p = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    pairs.append((param, value))
    return urlunparse(p._replace(query=urlencode(pairs)))


def get_context(body, marker):
    """Rough guess where the marker landed: html, attribute, script or none."""
    i = body.find(marker)  # marker can also be a whole payload
    if i == -1:
        return "none"
    before = body[:i]
    if before.lower().rfind("<script") > before.lower().rfind("</script"):
        return "script"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html"


def check_reflection(body, marker, payload_text, needle):
    """Returns (status, context). status: not reflected, encoded or UNENCODED."""
    if marker not in body:
        return "not reflected", "none"
    if needle in body and marker in body:
        # look at where the payload starts, not at the marker inside it
        return "UNENCODED", get_context(body, payload_text if payload_text in body else marker)
    return "encoded", get_context(body, marker)


def fetch(url, timeout=5):
    req = Request(url, headers={"User-Agent": "xss-tester/1.0"})
    opener = build_opener(ProxyHandler({}))  # no proxy, talk to the target directly
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.read().decode("utf-8", "replace")


def test_url(url, param, fetcher=fetch):
    findings = []
    for name, tpl, needle in PAYLOADS:
        marker = make_marker()
        payload = tpl.format(m=marker)
        body = fetcher(set_param(url, param, payload))
        status, ctx = check_reflection(body, marker, payload, needle)
        findings.append({"param": param, "payload": name, "status": status,
                         "context": ctx, "value": payload})
    return findings


def is_allowed(url, permission):
    return permission or urlparse(url).hostname in LOCAL_HOSTS


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reflected XSS tester")
    ap.add_argument("url", nargs="?")
    ap.add_argument("-p", "--param", help="parameter to test (default: all in URL)")
    ap.add_argument("-f", "--file", help="file with one URL per line")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="allow non-localhost targets")
    a = ap.parse_args(argv)
    urls = []
    if a.url:
        urls.append(a.url)
    if a.file:
        with open(a.file) as f:
            urls += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not urls:
        ap.error("give a URL or --file")
    results = []
    for u in urls:
        if not is_allowed(u, a.i_have_permission):
            print("[x] skipping %s (not localhost, use --i-have-permission if you are allowed)" % u)
            continue
        params = [a.param] if a.param else [k for k, _ in parse_qsl(urlparse(u).query)]
        for prm in params:
            results += [dict(r, url=u) for r in test_url(u, prm)]
    bad = [r for r in results if r["status"] == "UNENCODED"]
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in bad:
            print("[!] %s param=%s payload=%s context=%s" % (r["url"], r["param"], r["payload"], r["context"]))
        print("\n%d reflected XSS finding(s)" % len(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
