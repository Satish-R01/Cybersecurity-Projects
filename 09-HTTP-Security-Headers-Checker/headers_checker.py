#!/usr/bin/env python3
"""HTTP security headers checker.

Reads a saved HTTP response (headers) from a file and checks the
security headers. With --url it can also fetch headers from a target
you have permission to test.
"""
import argparse
import json
import re
import sys
import urllib.request

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def parse_response(text):
    """Parse a raw HTTP response (status line + headers) into (status, headers).
    Header names are lower-cased. Repeated headers (Set-Cookie) become lists."""
    status = None
    headers = {}
    for i, line in enumerate(text.splitlines()):
        line = line.rstrip("\r")
        if i == 0 and line.upper().startswith("HTTP/"):
            parts = line.split()
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            continue
        if not line.strip():
            break  # end of headers
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if name in headers:
            if not isinstance(headers[name], list):
                headers[name] = [headers[name]]
            headers[name].append(value)
        else:
            headers[name] = value
    return status, headers


def first(headers, name):
    v = headers.get(name)
    if isinstance(v, list):
        return v[0]
    return v


def finding(sev, code, msg):
    return {"severity": sev, "code": code, "message": msg}


def check_hsts(headers, https):
    v = first(headers, "strict-transport-security")
    if not https:
        return []
    if not v:
        return [finding("HIGH", "hsts_missing", "No Strict-Transport-Security. Browsers can be downgraded to HTTP (sslstrip).")]
    out = []
    m = re.search(r"max-age=(\d+)", v, re.I)
    if not m:
        out.append(finding("MEDIUM", "hsts_no_maxage", "HSTS has no max-age."))
    elif int(m.group(1)) < 15552000:
        out.append(finding("LOW", "hsts_short", "HSTS max-age is %s, less than 180 days." % m.group(1)))
    if "includesubdomains" not in v.lower():
        out.append(finding("LOW", "hsts_no_subdomains", "HSTS does not have includeSubDomains."))
    return out


def check_csp(headers):
    v = first(headers, "content-security-policy")
    if not v:
        return [finding("HIGH", "csp_missing", "No Content-Security-Policy. XSS has nothing to limit it.")]
    out = []
    low = v.lower()
    if "'unsafe-inline'" in low:
        out.append(finding("MEDIUM", "csp_unsafe_inline", "CSP allows 'unsafe-inline', which weakens XSS protection."))
    if "'unsafe-eval'" in low:
        out.append(finding("MEDIUM", "csp_unsafe_eval", "CSP allows 'unsafe-eval'."))
    if re.search(r"(^|[;\s])(default|script)-src[^;]*\s\*(\s|;|$)", low):
        out.append(finding("MEDIUM", "csp_wildcard", "CSP uses a * wildcard source for scripts."))
    if "default-src" not in low and "script-src" not in low:
        out.append(finding("MEDIUM", "csp_no_default", "CSP has no default-src or script-src."))
    if "frame-ancestors" not in low:
        out.append(finding("LOW", "csp_no_frame_ancestors", "CSP has no frame-ancestors (clickjacking is not covered by CSP)."))
    return out


def check_framing(headers):
    xfo = first(headers, "x-frame-options")
    csp = first(headers, "content-security-policy") or ""
    if "frame-ancestors" in csp.lower():
        return []
    if not xfo:
        return [finding("MEDIUM", "clickjacking", "No X-Frame-Options or frame-ancestors. The page can be framed (clickjacking).")]
    if xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return [finding("MEDIUM", "xfo_invalid", "X-Frame-Options value '%s' is not DENY or SAMEORIGIN." % xfo)]
    return []


def check_misc(headers):
    out = []
    xcto = first(headers, "x-content-type-options")
    if not xcto or xcto.strip().lower() != "nosniff":
        out.append(finding("LOW", "nosniff_missing", "X-Content-Type-Options: nosniff is missing (MIME sniffing)."))
    if not first(headers, "referrer-policy"):
        out.append(finding("LOW", "referrer_missing", "No Referrer-Policy. URLs with tokens may leak in the Referer header."))
    elif first(headers, "referrer-policy").strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        out.append(finding("LOW", "referrer_weak", "Referrer-Policy '%s' leaks full URLs." % first(headers, "referrer-policy")))
    if not first(headers, "permissions-policy"):
        out.append(finding("INFO", "permissions_missing", "No Permissions-Policy (camera, mic, geolocation are not restricted)."))
    return out


def check_leaks(headers):
    out = []
    server = first(headers, "server")
    if server and re.search(r"\d+\.\d+", server):
        out.append(finding("LOW", "server_version", "Server header shows a version: '%s'. Helps an attacker pick exploits." % server))
    for h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = first(headers, h)
        if v:
            out.append(finding("LOW", "leak_" + h.replace("-", "_"), "%s header shows '%s'." % (h, v)))
    return out


def check_cors(headers):
    out = []
    acao = first(headers, "access-control-allow-origin")
    acac = (first(headers, "access-control-allow-credentials") or "").lower()
    if acao == "*" and acac == "true":
        out.append(finding("HIGH", "cors_wildcard_creds", "CORS allows * with credentials."))
    elif acao == "*":
        out.append(finding("LOW", "cors_wildcard", "Access-Control-Allow-Origin is *. Fine for public data only."))
    elif acao == "null":
        out.append(finding("MEDIUM", "cors_null", "Access-Control-Allow-Origin is null, which sandboxed pages can abuse."))
    return out


def check_cookies(headers):
    cookies = headers.get("set-cookie") or []
    if not isinstance(cookies, list):
        cookies = [cookies]
    out = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        attrs = c.lower()
        if "secure" not in attrs:
            out.append(finding("MEDIUM", "cookie_no_secure", "Cookie '%s' has no Secure flag." % name))
        if "httponly" not in attrs:
            out.append(finding("MEDIUM", "cookie_no_httponly", "Cookie '%s' has no HttpOnly flag." % name))
        if "samesite" not in attrs:
            out.append(finding("LOW", "cookie_no_samesite", "Cookie '%s' has no SameSite attribute." % name))
    return out


def check_cache(headers):
    cc = (first(headers, "cache-control") or "").lower()
    if headers.get("set-cookie") and "no-store" not in cc and "private" not in cc:
        return [finding("LOW", "cache_with_cookie", "Response sets a cookie but Cache-Control has no no-store or private.")]
    return []


def analyze(headers, https=True):
    results = []
    results += check_hsts(headers, https)
    results += check_csp(headers)
    results += check_framing(headers)
    results += check_misc(headers)
    results += check_leaks(headers)
    results += check_cors(headers)
    results += check_cookies(headers)
    results += check_cache(headers)
    results.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return results


def score(findings):
    """Simple grade: start at 100, take points off per finding."""
    pts = {"HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}
    s = max(0, 100 - sum(pts[f["severity"]] for f in findings))
    grade = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
    return s, grade


def split_responses(text):
    """A sample file can hold many responses separated by a line of '###'.
    A line starting with '# url:' names the target."""
    blocks = []
    for block in re.split(r"(?m)^###\s*$", text):
        block = block.strip("\n")
        if not block.strip():
            continue
        url = "(unknown)"
        lines = block.splitlines()
        if lines and lines[0].startswith("# url:"):
            url = lines[0][6:].strip()
            block = "\n".join(lines[1:])
        blocks.append((url, block))
    return blocks


def fetch(url, timeout=10):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "headers-checker/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        lines = ["HTTP/1.1 %d %s" % (r.status, r.reason)]
        for k, v in r.headers.items():
            lines.append("%s: %s" % (k, v))
        return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check HTTP security headers from saved responses or a URL you may test.")
    ap.add_argument("file", nargs="?", help="file with raw responses (separated by ###)")
    ap.add_argument("--url", help="fetch headers from this URL (only with permission)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    if args.url:
        items = [(args.url, fetch(args.url))]
    elif args.file:
        with open(args.file, encoding="utf-8") as f:
            items = split_responses(f.read())
    else:
        ap.error("give a file or --url")

    report = []
    bad = False
    for url, raw in items:
        status, headers = parse_response(raw)
        findings = analyze(headers, https=url.lower().startswith("https") or url == "(unknown)")
        s, grade = score(findings)
        if any(f["severity"] in ("HIGH", "MEDIUM") for f in findings):
            bad = True
        report.append({"url": url, "status": status, "score": s, "grade": grade, "findings": findings})

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for r in report:
            print("%s  (HTTP %s)  score %d  grade %s" % (r["url"], r["status"], r["score"], r["grade"]))
            for f in r["findings"]:
                print("  %-7s %-22s %s" % (f["severity"], f["code"], f["message"]))
            if not r["findings"]:
                print("  nothing found")
            print()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
