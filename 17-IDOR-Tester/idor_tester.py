#!/usr/bin/env python3
"""IDOR tester.
Logs in as one user (using a token), walks a range of object IDs in a URL
template and reports IDs that return data owned by someone else."""
import argparse
import http.client
import json
import sys
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
OWNER_KEYS = ("owner", "user", "username", "name", "owner_id", "user_id")


def fetch(url, token, timeout=5):
    p = urlparse(url)
    conn_cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(p.hostname, p.port, timeout=timeout)
    path = p.path + ("?" + p.query if p.query else "")
    headers = {"Authorization": "Bearer " + token} if token else {}
    try:
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        return r.status, body
    finally:
        conn.close()


def owner_of(body):
    """Return the owner value from a JSON body, or None."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    for k in OWNER_KEYS:
        if k in data:
            return str(data[k])
    return None


def classify(status, body, me):
    """Return 'idor', 'own', 'denied' or 'missing' for one response."""
    if status in (401, 403):
        return "denied"
    if status == 404 or status >= 400:
        return "missing"
    owner = owner_of(body)
    if owner is None:
        return "own" if status == 200 else "missing"
    return "own" if owner.lower() == me.lower() else "idor"


def scan(template, ids, token, me):
    results = []
    for i in ids:
        url = template.replace("{id}", str(i))
        status, body = fetch(url, token)
        results.append({"id": i, "url": url, "status": status,
                        "verdict": classify(status, body, me),
                        "owner": owner_of(body)})
    return results


def parse_ids(text):
    ids = []
    for part in text.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            ids.extend(range(int(a), int(b) + 1))
        elif part.strip():
            ids.append(int(part))
    return ids


def main():
    ap = argparse.ArgumentParser(description="Simple IDOR tester for your own lab or permitted targets")
    ap.add_argument("template", help="URL with {id}, e.g. http://127.0.0.1:8000/api/orders/{id}")
    ap.add_argument("--ids", required=True, help="e.g. 101-110 or 1,2,5")
    ap.add_argument("--token", required=True, help="bearer token of the user you are testing as")
    ap.add_argument("--me", required=True, help="name of that user (to compare with the owner field)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--i-have-permission", action="store_true")
    a = ap.parse_args()

    host = urlparse(a.template).hostname
    if host not in LOCAL_HOSTS and not a.i_have_permission:
        sys.exit("Refusing: %s is not localhost. Use --i-have-permission only if you are allowed to test it." % host)

    res = scan(a.template, parse_ids(a.ids), a.token, a.me)
    bad = [r for r in res if r["verdict"] == "idor"]
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            tag = "[!]" if r["verdict"] == "idor" else "[ ]"
            print("%s id=%s status=%s %s owner=%s" % (tag, r["id"], r["status"], r["verdict"], r["owner"]))
        print("\n%d IDOR finding(s)" % len(bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
