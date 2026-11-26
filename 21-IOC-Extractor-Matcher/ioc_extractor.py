#!/usr/bin/env python3
"""IOC Extractor and Matcher.

Reads a threat report or any text file, pulls out the indicators (IPs, domains,
URLs, hashes, emails, CVE IDs) and checks them against my local blocklist.
Handles defanged text like hxxp://evil[.]com and 10[.]0[.]0[.]1.
"""
import argparse
import ipaddress
import json
import re
import sys

# Words that look like domains but are file names in reports
FILE_EXT = {"exe", "dll", "txt", "doc", "docx", "pdf", "js", "ps1", "bat", "py",
            "zip", "png", "jpg", "sh", "log", "csv", "xml", "json", "html", "php",
            "bin", "dat", "tmp", "msi", "lnk", "vbs", "rar", "iso", "7z"}

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")


def refang(text):
    """Turn hxxp://evil[.]com into http://evil.com."""
    text = re.sub(r"hxxp", "http", text, flags=re.I)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", text, flags=re.I)
    text = re.sub(r"\[:\]", ":", text)
    text = re.sub(r"\[@\]|\[at\]|\(at\)", "@", text, flags=re.I)
    return text


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def valid_ipv4(value):
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract(text):
    """Return a dict of sorted unique indicators found in the text."""
    text = refang(text)
    found = {k: set() for k in ("ip", "domain", "url", "email", "cve", "sha256", "sha1", "md5")}

    for u in URL.findall(text):
        found["url"].add(u.rstrip(".,;"))
    for e in EMAIL.findall(text):
        found["email"].add(e.lower())
    for c in CVE.findall(text):
        found["cve"].add(c.upper())

    # hashes: longest first so a sha256 is not also counted as md5
    rest = text
    for name, rx in (("sha256", SHA256), ("sha1", SHA1), ("md5", MD5)):
        for h in rx.findall(rest):
            found[name].add(h.lower())
        rest = rx.sub(" ", rest)

    for ip in IPV4.findall(text):
        if valid_ipv4(ip) and is_public_ip(ip):
            found["ip"].add(ip)

    # domains, the domain part of an email is kept too
    for d in DOMAIN.findall(text):
        d = d.lower()
        tld = d.rsplit(".", 1)[-1]
        if tld in FILE_EXT or valid_ipv4(d):
            continue
        found["domain"].add(d)

    return {k: sorted(v) for k, v in found.items()}


def load_blocklist(path):
    """Blocklist lines look like: indicator,tag  (tag is optional)."""
    block = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            value, _, tag = line.partition(",")
            block[refang(value.strip()).lower()] = tag.strip() or "blocklist"
    return block


def host_of(url):
    m = re.match(r"https?://([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""


def match(iocs, block):
    """Check each indicator against the blocklist. A subdomain of a listed domain matches too."""
    hits = []
    for kind, values in iocs.items():
        for v in values:
            tag = block.get(v)
            if tag is None and kind == "domain":
                parts = v.split(".")
                for i in range(1, len(parts) - 1):
                    parent = ".".join(parts[i:])
                    if parent in block:
                        tag = block[parent]
                        break
            if tag is None and kind == "url":
                tag = block.get(host_of(v))
            if tag is not None:
                hits.append({"type": kind, "value": v, "tag": tag})
    return hits


def main():
    ap = argparse.ArgumentParser(description="Extract IOCs from text and match them with a blocklist")
    ap.add_argument("file", help="report or text file")
    ap.add_argument("-b", "--blocklist", help="blocklist file (indicator,tag per line)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args()

    with open(args.file, encoding="utf-8", errors="replace") as f:
        iocs = extract(f.read())
    hits = match(iocs, load_blocklist(args.blocklist)) if args.blocklist else []

    if args.json:
        print(json.dumps({"iocs": iocs, "matches": hits}, indent=2))
    else:
        total = sum(len(v) for v in iocs.values())
        print(f"[+] {total} indicators found")
        for kind, values in iocs.items():
            if values:
                print(f"\n{kind.upper()} ({len(values)})")
                for v in values:
                    print(f"  {v}")
        if args.blocklist:
            print(f"\n[!] {len(hits)} match(es) with the blocklist" if hits else "\n[+] no blocklist matches")
            for h in hits:
                print(f"  {h['type']:<7} {h['value']}  ->  {h['tag']}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
