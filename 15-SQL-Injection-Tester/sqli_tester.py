#!/usr/bin/env python3
"""SQL injection tester. Checks one URL parameter for error-based and
boolean-based SQL injection. Only use on targets you have permission to test."""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

# error text that different databases show when a query breaks
ERROR_PATTERNS = {
    "SQLite": r"sqlite3?\.|unrecognized token|incomplete input|near \".*\": syntax error",
    "MySQL": r"you have an error in your sql syntax|mysql_fetch|mariadb",
    "PostgreSQL": r"pg_query|syntax error at or near|unterminated quoted string",
    "MSSQL": r"unclosed quotation mark|microsoft ole db|sql server",
    "Oracle": r"ora-\d{5}|quoted string not properly terminated",
}

ERROR_PAYLOADS = ["'", "\"", "')", "1'", "\\"]

# (true payload, false payload, name)
BOOLEAN_PAIRS = [
    (" AND 1=1", " AND 1=2", "numeric AND"),
    ("' AND '1'='1", "' AND '1'='2", "string AND"),
    ("%' AND '1'='1' AND '%'='", "%' AND '1'='2' AND '%'='", "LIKE string AND"),
    (" OR 1=1", " OR 1=2", "numeric OR"),
]

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def find_db_error(body):
    """Return the database name if the body looks like a SQL error, else None."""
    for db, pattern in ERROR_PATTERNS.items():
        if re.search(pattern, body, re.I):
            return db
    return None


def same_page(a, b, tolerance=0.02):
    """Two bodies are the same if the length differs by less than tolerance."""
    if a == b:
        return True
    longest = max(len(a), len(b), 1)
    return abs(len(a) - len(b)) / longest < tolerance and a.split() == b.split()


def build_url(url, param, value):
    p = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    q.append((param, value))
    return urlunparse(p._replace(query=urlencode(q, safe="")))


def fetch(url, timeout=5):
    """Return (status, body). Does not raise on 4xx and 5xx."""
    # no proxy: the tool talks to the target directly
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def test_param(url, param, fetcher=fetch):
    """Run all checks on one parameter and return a list of findings."""
    findings = []
    base_value = dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).get(param, "")
    _, base_body = fetcher(build_url(url, param, base_value))

    for payload in ERROR_PAYLOADS:
        status, body = fetcher(build_url(url, param, base_value + payload))
        db = find_db_error(body)
        if db and not find_db_error(base_body):
            findings.append({"param": param, "type": "error-based", "payload": payload,
                             "evidence": "%s error, status %d" % (db, status)})
            break

    for true_p, false_p, name in BOOLEAN_PAIRS:
        _, t_body = fetcher(build_url(url, param, base_value + true_p))
        _, f_body = fetcher(build_url(url, param, base_value + false_p))
        # true should look like the normal page, false should not
        if same_page(base_body, t_body) and not same_page(t_body, f_body):
            findings.append({"param": param, "type": "boolean-based", "payload": name,
                             "evidence": "true=%d bytes, false=%d bytes" % (len(t_body), len(f_body))})
            break
    return findings


def main():
    ap = argparse.ArgumentParser(description="Simple SQL injection tester")
    ap.add_argument("url", help="URL with a parameter, e.g. http://127.0.0.1:8000/product?id=1")
    ap.add_argument("-p", "--param", help="parameter to test (default: all)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="needed to test anything that is not localhost")
    a = ap.parse_args()

    host = urlparse(a.url).hostname
    if host not in LOCAL_HOSTS and not a.i_have_permission:
        print("Refusing: %s is not localhost. Use --i-have-permission only if you are allowed to test it." % host)
        return 2

    params = [a.param] if a.param else [k for k, _ in parse_qsl(urlparse(a.url).query)]
    if not params:
        print("No parameters found in the URL.")
        return 2

    findings = []
    for p in params:
        findings += test_param(a.url, p)

    if a.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print("[!] param=%s %s payload=%s (%s)" % (f["param"], f["type"], f["payload"], f["evidence"]))
        print("\n%d SQL injection finding(s)" % len(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
