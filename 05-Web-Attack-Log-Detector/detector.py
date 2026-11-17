#!/usr/bin/env python3
"""Find common web attacks in Apache/Nginx access logs (combined format)."""
import argparse
import json
import re
import sys
from collections import defaultdict
from urllib.parse import unquote_plus

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

RULES = {
    "SQLi": [
        r"union(\s|/\*.*?\*/)+(all\s+)?select",
        r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"'\s*(or|and)\s+'",
        r"\w'(\s|$|&)",
        r"(--|#)\s*$",
        r"\b(sleep|benchmark)\s*\(",
        r"information_schema",
        r"\bdrop\s+table\b",
        r"\bselect\b.+\bfrom\b",
    ],
    "XSS": [
        r"<\s*script",
        r"javascript:",
        r"\bon(error|load|mouseover|focus)\s*=",
        r"<\s*(img|svg|iframe)[^>]*>",
        r"document\.cookie",
    ],
    "Path traversal": [
        r"\.\./",
        r"\.\.\\",
        r"/etc/(passwd|shadow)",
        r"boot\.ini",
        r"win\.ini",
    ],
    "Command injection": [
        r"[;|&`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b",
        r"\$\(.+\)",
    ],
}

SCANNER_UAS = ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
               "wfuzz", "acunetix", "nessus", "openvas", "zgrab", "hydra"]

COMPILED = {k: [re.compile(p, re.I) for p in v] for k, v in RULES.items()}


def parse_line(line):
    m = LOG_RE.match(line.strip())
    return m.groupdict() if m else None


def decode(path):
    # decode twice, attackers sometimes double encode
    return unquote_plus(unquote_plus(path))


def check_entry(e):
    """Return list of attack types found in one parsed log entry."""
    found = []
    text = decode(e["path"])
    for name, patterns in COMPILED.items():
        if any(p.search(text) for p in patterns):
            found.append(name)
    ua = (e.get("ua") or "").lower()
    if any(s in ua for s in SCANNER_UAS):
        found.append("Scanner")
    return found


def analyze(lines, scan_404=10):
    findings = []
    per_ip = defaultdict(lambda: {"requests": 0, "404": 0, "types": set(), "paths404": set()})
    bad_lines = 0
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        e = parse_line(line)
        if not e:
            bad_lines += 1
            continue
        st = per_ip[e["ip"]]
        st["requests"] += 1
        if e["status"] == "404":
            st["404"] += 1
            st["paths404"].add(e["path"])
        for t in check_entry(e):
            st["types"].add(t)
            findings.append({"line": n, "ip": e["ip"], "type": t, "status": e["status"],
                             "path": e["path"], "time": e["time"]})
    # many 404s from one IP = directory scanning
    for ip, st in per_ip.items():
        if st["404"] >= scan_404:
            st["types"].add("Forced browsing")
            findings.append({"line": 0, "ip": ip, "type": "Forced browsing", "status": "404",
                             "path": f"{st['404']} not-found requests", "time": ""})
    return findings, per_ip, bad_lines


def risk(types):
    return "HIGH" if types & {"SQLi", "Command injection", "Path traversal"} else "MEDIUM"


def main():
    ap = argparse.ArgumentParser(description="Detect web attacks in an access log")
    ap.add_argument("logfile")
    ap.add_argument("--scan-404", type=int, default=10, help="404s from one IP before flagging forced browsing")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    a = ap.parse_args()

    with open(a.logfile, errors="replace") as f:
        findings, per_ip, bad = analyze(f, a.scan_404)

    if a.json:
        print(json.dumps(findings, indent=2))
        return 1 if findings else 0

    if not findings:
        print("No attacks found.")
        return 0

    print(f"[!] {len(findings)} suspicious request(s) from {len({x['ip'] for x in findings})} IP(s)\n")
    print("Per IP summary:")
    for ip, st in sorted(per_ip.items(), key=lambda x: -len(x[1]["types"])):
        if st["types"]:
            print(f"  {ip:<16} {risk(st['types']):<7} requests={st['requests']:<3} {', '.join(sorted(st['types']))}")
    print("\nDetails:")
    for x in findings:
        if x["line"]:
            print(f"  line {x['line']:<3} {x['ip']:<16} {x['type']:<18} {x['status']} {x['path'][:70]}")
        else:
            print(f"        {x['ip']:<16} {x['type']:<18} {x['path']}")
    if bad:
        print(f"\n{bad} line(s) could not be parsed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
