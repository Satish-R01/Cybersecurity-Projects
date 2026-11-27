#!/usr/bin/env python3
"""Directory and file fuzzer.

Tries paths from a wordlist on one base URL and lists the ones that exist.
It first asks for a random path that cannot exist, so a "soft 404" page
(200 status but says not found) is not reported as a finding.
Only use it on targets you own or have permission to test.
"""
import argparse
import json
import random
import string
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_WORDS = 2000

# names that are risky if they are reachable
HIGH = (".git", ".env", ".svn", "backup", ".bak", ".sql", ".zip", ".old",
        "phpinfo", "id_rsa", ".htpasswd", "dump")
MEDIUM = ("admin", "config", "console", "server-status", "test", "dev",
          "uploads", "manager", "debug")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects, we want to see the 301/302 itself."""
    def redirect_request(self, *a, **k):
        return None


# no proxy, so local lab traffic stays on this machine
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def load_words(path, extensions=()):
    with open(path) as f:
        words = [l.strip().lstrip("/") for l in f if l.strip() and not l.startswith("#")]
    out = []
    for w in words:
        out.append(w)
        for ext in extensions:
            if "." not in w.split("/")[-1]:
                out.append(w + ext)
    seen = set()
    return [w for w in out if not (w in seen or seen.add(w))]


def fetch(url, timeout=5):
    """Return (status, body, headers) for a GET without following redirects."""
    req = urllib.request.Request(url, headers={"User-Agent": "dir-fuzzer/1.0"})
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read(200000), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(200000), dict(e.headers)
    except (urllib.error.URLError, OSError):
        return 0, b"", {}


def normalize(body, word):
    """Replace the requested path in the body, because many 404 pages echo it."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    return text.replace(word, "{P}")


def calibrate(base, fetcher=fetch, tries=2):
    """Request random paths that should not exist and remember how they look."""
    sigs = []
    for _ in range(tries):
        junk = "".join(random.choice(string.ascii_lowercase) for _ in range(14))
        status, body, _h = fetcher(base + "/" + junk)
        sigs.append({"status": status, "length": len(body), "junk": junk,
                     "shape": normalize(body, junk)})
    return sigs


def looks_like_404(status, body, sigs, word=""):
    """True if the response matches what a missing page looked like."""
    for s in sigs:
        if status != s["status"]:
            continue
        if status in (404, 410):
            return True
        # soft 404: same status and the same page once the path is swapped out
        if word and normalize(body, word) == s["shape"]:
            return True
        if not word and abs(len(body) - s["length"]) <= 5:
            return True
    return False


def risk(path, status):
    low = path.lower()
    if status in (404, 410, 0):
        return "none"
    if any(k in low for k in HIGH) and status == 200:
        return "high"
    if any(k in low for k in MEDIUM):
        return "medium"
    if status == 200:
        return "low"
    return "info"


def interesting(status):
    return status in (200, 204, 301, 302, 307, 308, 401, 403, 405, 500)


def run(base, words, delay=0.0, fetcher=fetch):
    base = base.rstrip("/")
    sigs = calibrate(base, fetcher)
    if any(s["status"] == 0 for s in sigs):
        raise RuntimeError("could not reach %s" % base)
    findings = []
    for w in words:
        status, body, headers = fetcher(base + "/" + w)
        if interesting(status) and not looks_like_404(status, body, sigs, w):
            h = {k.lower(): v for k, v in headers.items()}
            findings.append({"path": "/" + w, "status": status, "length": len(body),
                             "redirect": h.get("location"), "risk": risk(w, status)})
        if delay:
            time.sleep(delay)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3, "none": 4}
    findings.sort(key=lambda f: (order[f["risk"]], f["path"]))
    return {"base": base, "tried": len(words), "soft_404": sigs[0]["status"] == 200,
            "findings": findings}


def check_target(url, allow):
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS and not allow:
        sys.exit("Refusing to test %s. Use --i-have-permission only if you are allowed to test it." % host)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Directory and file fuzzer")
    ap.add_argument("url", help="base URL, for example http://127.0.0.1:8000")
    ap.add_argument("--wordlist", default="samples/wordlist.txt")
    ap.add_argument("--extensions", default="", help="comma list, for example .bak,.zip")
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--i-have-permission", action="store_true")
    a = ap.parse_args(argv)
    check_target(a.url, a.i_have_permission)
    exts = [e if e.startswith(".") else "." + e for e in a.extensions.split(",") if e]
    words = load_words(a.wordlist, exts)
    if len(words) > MAX_WORDS:
        sys.exit("Wordlist is too big (%d). Keep it at %d or less." % (len(words), MAX_WORDS))
    try:
        rep = run(a.url, words, a.delay)
    except RuntimeError as e:
        sys.exit(str(e))
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        if rep["soft_404"]:
            print("Note: this site answers 200 for missing pages. Those were filtered out.\n")
        for f in rep["findings"]:
            extra = " -> %s" % f["redirect"] if f["redirect"] else ""
            print("[%-6s] %d %-18s %5d bytes%s" % (f["risk"].upper(), f["status"], f["path"], f["length"], extra))
        print("\nTried %d paths, found %d." % (rep["tried"], len(rep["findings"])))
    return 1 if any(f["risk"] == "high" for f in rep["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
