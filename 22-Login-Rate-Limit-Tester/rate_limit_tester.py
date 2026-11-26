#!/usr/bin/env python3
"""Login rate limit tester.

Sends a fixed number of wrong-password logins to one account and checks if
the server ever slows down, blocks or locks the account.
Only use it on targets you own or have permission to test.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
LOCK_WORDS = ("locked", "too many", "try again later", "rate limit", "captcha")


def load_passwords(path, count):
    with open(path) as f:
        words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not words:
        raise ValueError("password file is empty")
    # repeat the list if we need more attempts than words
    return [words[i % len(words)] for i in range(count)]


def classify(status, body, headers):
    """Return 'blocked' if the response looks like a limit, else 'allowed'."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    if status in (429, 423):
        return "blocked"
    if "retry-after" in h:
        return "blocked"
    low = (body or "").lower()
    if status != 200 and any(w in low for w in LOCK_WORDS):
        return "blocked"
    return "allowed"


def send_login(url, user, password, timeout=5):
    data = json.dumps({"username": user, "password": password}).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    start = time.time()
    try:
        # no proxy, so local lab traffic stays on this machine
        with OPENER.open(req, timeout=timeout) as r:
            status, body, headers = r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        status, body, headers = e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    return status, body, headers, time.time() - start


def run(url, user, passwords, delay=0.0, sender=send_login):
    results = []
    first_block = None
    for i, pw in enumerate(passwords, 1):
        status, body, headers, took = sender(url, user, pw)
        verdict = classify(status, body, headers)
        results.append({"attempt": i, "status": status, "verdict": verdict,
                        "seconds": round(took, 3),
                        "retry_after": {k.lower(): v for k, v in headers.items()}.get("retry-after")})
        if verdict == "blocked" and first_block is None:
            first_block = i
        if delay:
            time.sleep(delay)
    return {"url": url, "user": user, "attempts": len(results),
            "first_block": first_block, "vulnerable": first_block is None,
            "results": results}


def check_target(url, allow):
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS and not allow:
        sys.exit("Refusing to test %s. Use --i-have-permission only if you are allowed to test it." % host)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Login rate limit tester")
    ap.add_argument("url", help="login URL, for example http://127.0.0.1:8000/vuln/login")
    ap.add_argument("--user", required=True)
    ap.add_argument("--passwords", default="samples/passwords.txt")
    ap.add_argument("--attempts", type=int, default=15)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--i-have-permission", action="store_true")
    a = ap.parse_args(argv)
    check_target(a.url, a.i_have_permission)
    if a.attempts > 100:
        sys.exit("Keep --attempts at 100 or less. This is a limit check, not a brute force.")
    rep = run(a.url, a.user, load_passwords(a.passwords, a.attempts), a.delay)
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        for r in rep["results"]:
            tag = "[!]" if r["verdict"] == "blocked" else "[ ]"
            extra = " retry-after=%s" % r["retry_after"] if r["retry_after"] else ""
            print("%s attempt=%d status=%d %s%s" % (tag, r["attempt"], r["status"], r["verdict"], extra))
        if rep["vulnerable"]:
            print("\nNo limit after %d wrong logins. Brute force is possible." % rep["attempts"])
        else:
            print("\nBlocked at attempt %d. A limit exists." % rep["first_block"])
    return 1 if rep["vulnerable"] else 0


if __name__ == "__main__":
    sys.exit(main())
