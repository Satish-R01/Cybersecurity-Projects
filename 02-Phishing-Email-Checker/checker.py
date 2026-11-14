#!/usr/bin/env python3
"""
Phishing Email Checker
Reads .eml files and looks for common phishing signs: failed SPF/DKIM/DMARC,
From / Reply-To mismatch, lookalike domains, bad links, urgency words and
risky attachments. Gives each email a risk score.
Author: Satish R
"""
import argparse, json, re, sys
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

BRANDS = ["paypal", "microsoft", "office365", "outlook", "google", "apple", "amazon",
          "netflix", "linkedin", "facebook", "instagram", "dropbox", "docusign",
          "sbi", "onlinesbi", "hdfcbank", "icicibank", "axisbank", "paytm"]
KNOWN_GOOD = {"microsoftonline.com", "googleusercontent.com", "amazonaws.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
URGENCY = ["urgent", "immediately", "suspended", "verify your account", "within 24 hours",
           "unusual activity", "password expires", "action required", "final notice",
           "confirm your identity", "account will be closed", "limited time"]
RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso",
             ".img", ".lnk", ".html", ".htm", ".docm", ".xlsm", ".jar", ".zip", ".rar"}
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)
HREF_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)


def domain_of(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def base_domain(host):
    parts = host.lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def lookalike(host):
    """Returns the brand a domain is trying to look like, or None."""
    if base_domain(host) in KNOWN_GOOD:
        return None
    name = base_domain(host).split(".")[0]
    if name in BRANDS:
        return None
    norm = name.translate(str.maketrans("013457", "oleast")).replace("rn", "m").replace("vv", "w")
    for brand in BRANDS:
        if norm == brand or (len(brand) > 4 and brand in norm):
            return brand
        if len(brand) > 4 and SequenceMatcher(None, name, brand).ratio() >= 0.85:
            return brand
    return None


def auth_results(msg):
    text = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    text += " " + " ".join("spf=" + str(h).split()[0] for h in (msg.get_all("Received-SPF") or []))
    res = {}
    for check in ("spf", "dkim", "dmarc"):
        m = re.search(check + r"=(\w+)", text, re.I)
        res[check] = m.group(1).lower() if m else "none"
    return res


def get_bodies(msg):
    text, html, attachments = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name or part.get_content_disposition() == "attachment":
            attachments.append(name or "unnamed")
        elif part.get_content_type() == "text/plain":
            text += part.get_content()
        elif part.get_content_type() == "text/html":
            html += part.get_content()
    return text, html, attachments


def check_url(url):
    issues = []
    host = (urlparse(url).hostname or "").lower()
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        issues.append("uses an IP address")
    if host in SHORTENERS:
        issues.append("URL shortener")
    if "xn--" in host:
        issues.append("punycode domain")
    if "@" in urlparse(url).netloc:
        issues.append("@ in URL")
    if url.lower().startswith("http://"):
        issues.append("not HTTPS")
    brand = lookalike(host) if host else None
    if brand:
        issues.append(f"lookalike of {brand}")
    return host, issues


def analyze(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    findings = []  # (points, reason)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))
    from_dom = domain_of(from_addr)

    auth = auth_results(msg)
    for check, points in (("spf", 15), ("dkim", 15), ("dmarc", 20)):
        if auth[check] in ("fail", "softfail", "permerror"):
            findings.append((points, f"{check.upper()} {auth[check]}"))
        elif auth[check] in ("none", "neutral", "temperror"):
            findings.append((5, f"{check.upper()} {auth[check]}"))

    if reply_addr and base_domain(domain_of(reply_addr)) != base_domain(from_dom):
        findings.append((20, f"Reply-To ({reply_addr}) differs from From ({from_addr})"))
    if return_addr and base_domain(domain_of(return_addr)) != base_domain(from_dom):
        findings.append((10, f"Return-Path ({return_addr}) differs from From domain"))

    brand = lookalike(from_dom)
    if brand:
        findings.append((25, f"Sender domain {from_dom} looks like {brand}"))
    for b in BRANDS:
        if len(b) > 3 and b in from_name.lower().replace(" ", "") and b not in from_dom:
            findings.append((15, f"Display name '{from_name}' uses {b} but sends from {from_dom}"))
            break

    text, html, attachments = get_bodies(msg)
    urls = set(URL_RE.findall(text)) | set(URL_RE.findall(html))
    for href, label in HREF_RE.findall(html):
        shown = URL_RE.search(re.sub("<[^>]+>", "", label))
        if shown and urlparse(shown.group()).hostname != urlparse(href).hostname:
            findings.append((20, f"Link text shows {shown.group()} but goes to {href}"))
    bad_urls = []
    for url in sorted(urls):
        host, issues = check_url(url)
        if issues:
            bad_urls.append({"url": url, "issues": issues})
            findings.append((10 + 5 * len(issues), f"{url} ({', '.join(issues)})"))

    content = (str(msg.get("Subject", "")) + " " + text + " " + re.sub("<[^>]+>", " ", html)).lower()
    words = [w for w in URGENCY if w in content]
    if words:
        findings.append((min(5 * len(words), 20), "Urgency words: " + ", ".join(words)))

    for name in attachments:
        exts = re.findall(r"\.[a-z0-9]+", name.lower())
        if exts and exts[-1] in RISKY_EXT:
            extra = " (double extension)" if len(exts) > 1 else ""
            findings.append((30, f"Risky attachment: {name}{extra}"))

    score = min(sum(p for p, _ in findings), 100)
    verdict = "PHISHING" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOW RISK"
    return {
        "file": path, "subject": str(msg.get("Subject", "")), "from": from_addr,
        "reply_to": reply_addr, "auth": auth, "urls": sorted(urls), "bad_urls": bad_urls,
        "attachments": attachments, "score": score, "verdict": verdict,
        "findings": [r for _, r in sorted(findings, reverse=True)],
    }


def print_report(r):
    print(f"\n=== {r['file']}")
    print(f"Subject : {r['subject']}")
    print(f"From    : {r['from']}" + (f"   Reply-To: {r['reply_to']}" if r["reply_to"] else ""))
    print("Auth    : " + "  ".join(f"{k.upper()}={v}" for k, v in r["auth"].items()))
    print(f"Score   : {r['score']}/100  ->  {r['verdict']}")
    for f in r["findings"]:
        print(f"  - {f}")


def main():
    ap = argparse.ArgumentParser(description="Check .eml files for phishing signs")
    ap.add_argument("files", nargs="+", help=".eml file(s)")
    ap.add_argument("--json", help="save results to a JSON file")
    args = ap.parse_args()

    results = []
    for path in args.files:
        try:
            results.append(analyze(path))
        except OSError as e:
            print(f"[x] cannot read {path}: {e}", file=sys.stderr)
    for r in results:
        print_report(r)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
