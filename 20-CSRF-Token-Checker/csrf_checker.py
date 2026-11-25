"""CSRF token checker.
Finds POST forms on a page and tests how the server treats the CSRF token.
Use only on targets you own or have permission to test."""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

TOKEN_NAMES = ("csrf", "xsrf", "token", "authenticity", "nonce")
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class FormParser(HTMLParser):
    """Collects forms and their input fields."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"method": (a.get("method") or "get").lower(),
                        "action": a.get("action", ""), "fields": {}}
            self.forms.append(self.cur)
        elif tag in ("input", "textarea", "select") and self.cur is not None:
            if a.get("name"):
                self.cur["fields"][a["name"]] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


def parse_forms(html):
    p = FormParser()
    p.feed(html)
    return p.forms


def find_token_field(fields):
    for name in fields:
        if any(w in name.lower() for w in TOKEN_NAMES):
            return name
    return None


def parse_cookie_flags(set_cookie):
    """Returns (name, flags dict) from one Set-Cookie header value."""
    parts = [x.strip() for x in set_cookie.split(";")]
    name = parts[0].split("=")[0]
    flags = {"httponly": False, "secure": False, "samesite": None}
    for x in parts[1:]:
        low = x.lower()
        if low == "httponly":
            flags["httponly"] = True
        elif low == "secure":
            flags["secure"] = True
        elif low.startswith("samesite="):
            flags["samesite"] = low.split("=", 1)[1]
    return name, flags


# no proxy, so requests to localhost stay on localhost
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http(url, data=None, cookie=""):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        r = OPENER.open(req, timeout=5)
        return r.status, r.read().decode(errors="replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), e.headers


def cookie_of(headers):
    sc = headers.get("Set-Cookie", "")
    return sc.split(";")[0] if sc else ""


def check(url):
    findings = []
    status, html, headers = http(url)
    cookie = cookie_of(headers)
    sc = headers.get("Set-Cookie")
    if sc:
        name, fl = parse_cookie_flags(sc)
        if fl["samesite"] not in ("strict", "lax"):
            findings.append(("MEDIUM", f"cookie {name} has no SameSite=Lax/Strict"))
    forms = [f for f in parse_forms(html) if f["method"] == "post"]
    if not forms:
        return findings + [("INFO", "no POST forms found")]
    for form in forms:
        target = urllib.parse.urljoin(url, form["action"])
        tf = find_token_field(form["fields"])
        base = dict(form["fields"])
        if not tf:
            findings.append(("HIGH", f"form {form['action']} has no CSRF token field"))
            code, _, _ = http(target, base, cookie)
            if code == 200:
                findings.append(("HIGH", f"{form['action']} accepts the POST with no token"))
            continue
        good = form["fields"][tf]
        if len(good) < 16:
            findings.append(("MEDIUM", f"token in {tf} is short ({len(good)} chars)"))
        # second visit with no cookie: a per-session token must change
        _, html2, h2 = http(url)
        f2 = [f for f in parse_forms(html2) if f["method"] == "post"]
        if f2 and f2[0]["fields"].get(tf) == good:
            findings.append(("HIGH", f"token in {tf} is the same for different sessions"))
        tests = {"missing": None, "empty": "", "wrong": "x" * len(good)}
        for label, val in tests.items():
            data = dict(base)
            if val is None:
                data.pop(tf)
            else:
                data[tf] = val
            code, _, _ = http(target, data, cookie)
            if code == 200:
                findings.append(("HIGH", f"{form['action']} accepts a {label} token"))
        # a token from another session
        other_cookie = cookie_of(h2)
        code, _, _ = http(target, base, other_cookie)
        if code == 200 and other_cookie != cookie:
            findings.append(("HIGH", f"{form['action']} accepts a token from another session"))
    if not any(s == "HIGH" for s, _ in findings):
        findings.append(("INFO", "token is checked by the server"))
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check CSRF protection on a form page")
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--i-have-permission", action="store_true")
    a = ap.parse_args(argv)
    host = urllib.parse.urlparse(a.url).hostname
    if host not in LOCAL_HOSTS and not a.i_have_permission:
        print("Not localhost. Pass --i-have-permission only if you may test it.")
        return 2
    findings = check(a.url)
    if a.json:
        print(json.dumps([{"severity": s, "message": m} for s, m in findings], indent=2))
    else:
        for s, m in findings:
            print(f"[{s}] {m}")
    return 1 if any(s == "HIGH" for s, _ in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
