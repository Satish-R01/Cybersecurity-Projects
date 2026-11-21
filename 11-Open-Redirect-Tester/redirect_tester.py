#!/usr/bin/env python3
"""Open redirect tester.
Tries redirect payloads on URL parameters and checks if the Location
header sends the browser to another host. Does not follow redirects."""
import argparse
import http.client
import json
import sys
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

EVIL = "evil.example"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# payloads: (name, value). {t} is the target host.
PAYLOADS = [
    ("absolute url", "https://%s/" % EVIL),
    ("protocol relative", "//%s/" % EVIL),
    ("backslash", "/\\%s" % EVIL),
    ("triple slash", "///%s" % EVIL),
    ("userinfo trick", "http://{t}@%s/" % EVIL),
    ("trusted prefix", "http://{t}.%s/" % EVIL),
    ("scheme without slashes", "https:%s" % EVIL),
    ("encoded slashes", "%2f%2f" + EVIL),
    ("javascript scheme", "javascript:alert(1)"),
]


def host_of(location, base_host):
    """Return the host a Location header points to (base_host if relative)."""
    loc = location.strip().replace("\\", "/")
    if loc.lower().startswith("javascript:"):
        return "javascript:"
    if loc.startswith("//"):
        loc = "http:" + loc
    p = urlparse(loc)
    if p.scheme in ("http", "https"):
        return (p.hostname or "").lower()
    if p.scheme and not p.netloc:
        # something like https:evil.example
        rest = loc.split(":", 1)[1].lstrip("/")
        return rest.split("/")[0].lower()
    return base_host


def is_redirect_to_other_host(location, base_host):
    h = host_of(location, base_host)
    return h != base_host.lower()


def build_url(url, param, value):
    p = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(p.query) if k != param]
    q.append((param, value))
    return urlunparse(p._replace(query=urlencode(q, safe="/:@\\%")))


def fetch(url, timeout=5):
    p = urlparse(url)
    conn_cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(p.hostname, p.port, timeout=timeout)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    conn.request("GET", path, headers={"User-Agent": "redirect-tester"})
    r = conn.getresponse()
    status, loc = r.status, r.getheader("Location", "")
    conn.close()
    return status, loc


def test_param(url, param, fetcher=fetch):
    base_host = urlparse(url).hostname
    findings = []
    for name, val in PAYLOADS:
        val = val.replace("{t}", base_host)
        test_url = build_url(url, param, val)
        try:
            status, loc = fetcher(test_url)
        except OSError as e:
            findings.append({"param": param, "payload": name, "error": str(e)})
            continue
        if 300 <= status < 400 and loc and is_redirect_to_other_host(loc, base_host):
            findings.append({"param": param, "payload": name, "status": status,
                             "location": loc, "url": test_url})
    return findings


def load_targets(path):
    """File format: one URL per line, # for comments. The URL has the param in it."""
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Open redirect tester")
    ap.add_argument("url", nargs="?", help="URL with the parameter, e.g. http://127.0.0.1:8000/login?next=/")
    ap.add_argument("-p", "--param", action="append", help="parameter to test (default: all in the URL)")
    ap.add_argument("-f", "--file", help="file with one URL per line")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="needed to test hosts that are not localhost")
    a = ap.parse_args(argv)

    urls = load_targets(a.file) if a.file else ([a.url] if a.url else [])
    if not urls:
        ap.error("give a URL or --file")

    results = []
    for u in urls:
        host = urlparse(u).hostname
        if host not in LOCAL_HOSTS and not a.i_have_permission:
            print("Skipping %s: not localhost. Use --i-have-permission only if you may test it." % u,
                  file=sys.stderr)
            continue
        params = a.param or [k for k, _ in parse_qsl(urlparse(u).query)]
        for prm in params:
            results.extend(test_param(u, prm))

    hits = [r for r in results if "location" in r]
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if "error" in r:
                print("[?] %s / %s: %s" % (r["param"], r["payload"], r["error"]))
            else:
                print("[!] param=%s payload=%s -> %s %s" % (r["param"], r["payload"], r["status"], r["location"]))
        print("\n%d open redirect finding(s)" % len(hits))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
