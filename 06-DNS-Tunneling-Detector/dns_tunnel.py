#!/usr/bin/env python3
"""Find possible DNS tunneling and DNS exfiltration in Zeek dns.log files."""
import argparse
import binascii
import json
import math
import sys
from collections import Counter, defaultdict

# public suffixes with two parts, so example.co.uk gives example.co.uk and not co.uk
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "org.in", "net.in",
                     "gov.in", "ac.in", "com.au", "net.au", "co.jp", "com.br", "co.za"}


def read_zeek(lines):
    """Read Zeek dns.log in TSV (default) or JSON format. Yields dicts."""
    fields = None
    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except ValueError:
                continue
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or fields is None:
            continue
        values = line.split("\t")
        if len(values) == len(fields):
            yield dict(zip(fields, values))


def base_domain(name):
    name = name.lower().rstrip(".")
    parts = name.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def subdomain(name, base):
    name = name.lower().rstrip(".")
    if name == base:
        return ""
    return name[: -len(base) - 1]


def entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def try_decode(sub):
    """Try hex decoding the subdomain. Returns readable text or ''."""
    data = "".join(p for p in sub.split(".") if all(c in "0123456789abcdef" for c in p) and len(p) >= 8)
    if len(data) < 8 or len(data) % 2:
        return ""
    try:
        text = binascii.unhexlify(data).decode("ascii")
    except (binascii.Error, UnicodeDecodeError):
        return ""
    if sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) > 0.9:
        return text.replace("\n", "\\n")
    return ""


def analyze(records, min_queries=20, allowlist=()):
    """Group queries by (client IP, base domain) and score each group."""
    groups = defaultdict(lambda: {"queries": 0, "subs": set(), "qtypes": Counter(),
                                  "nx": 0, "lengths": [], "entropies": [], "first": None,
                                  "last": None, "decoded": ""})
    for r in records:
        q = (r.get("query") or "").strip()
        if not q or q == "-":
            continue
        base = base_domain(q)
        if base in allowlist:
            continue
        g = groups[(r.get("id.orig_h", "?"), base)]
        sub = subdomain(q, base)
        g["queries"] += 1
        g["subs"].add(sub)
        g["qtypes"][r.get("qtype_name", "-")] += 1
        if r.get("rcode_name") == "NXDOMAIN":
            g["nx"] += 1
        g["lengths"].append(len(sub))
        # short names like www or mail don't say much, only score long ones
        if len(sub) >= 10:
            g["entropies"].append(entropy(sub.replace(".", "")))
        ts = r.get("ts")
        g["first"] = g["first"] or ts
        g["last"] = ts
        if not g["decoded"]:
            g["decoded"] = try_decode(sub)

    alerts = []
    for (client, base), g in groups.items():
        if g["queries"] < min_queries:
            continue
        reasons = []
        score = 0
        max_len = max(g["lengths"])
        avg_len = sum(g["lengths"]) / len(g["lengths"])
        avg_ent = sum(g["entropies"]) / len(g["entropies"]) if g["entropies"] else 0.0
        unique_ratio = len(g["subs"]) / g["queries"]
        txt_null = g["qtypes"]["TXT"] + g["qtypes"]["NULL"]
        if max_len >= 50 or avg_len >= 30:
            score += 2
            reasons.append(f"long subdomains (avg {avg_len:.0f}, max {max_len})")
        if avg_ent >= 3.5:
            score += 2
            reasons.append(f"high entropy ({avg_ent:.2f})")
        if unique_ratio >= 0.8:
            score += 2
            reasons.append(f"{len(g['subs'])} unique subdomains")
        if txt_null / g["queries"] >= 0.5:
            score += 1
            reasons.append(f"{txt_null} TXT/NULL queries")
        if g["nx"] / g["queries"] >= 0.5:
            score += 1
            reasons.append(f"{g['nx']} NXDOMAIN")
        if g["decoded"]:
            score += 1
            reasons.append("hex data in name")
        if score >= 5:
            sev = "HIGH"
        elif score >= 3:
            sev = "MEDIUM"
        else:
            continue
        alerts.append({"severity": sev, "score": score, "client": client, "domain": base,
                       "queries": g["queries"], "unique_subdomains": len(g["subs"]),
                       "avg_length": round(avg_len, 1), "max_length": max_len,
                       "avg_entropy": round(avg_ent, 2), "qtypes": dict(g["qtypes"]),
                       "first_seen": g["first"], "last_seen": g["last"],
                       "reasons": reasons, "decoded_sample": g["decoded"][:60]})
    alerts.sort(key=lambda a: (-a["score"], -a["queries"]))
    return alerts


def load_allowlist(path):
    if not path:
        return set()
    with open(path) as f:
        return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}


def main():
    ap = argparse.ArgumentParser(description="Detect DNS tunneling in Zeek dns.log")
    ap.add_argument("logfile")
    ap.add_argument("-m", "--min-queries", type=int, default=20,
                    help="queries from one client to one domain before it is checked (default 20)")
    ap.add_argument("-a", "--allowlist", help="file with domains to skip, one per line")
    ap.add_argument("--json", action="store_true", help="print alerts as JSON")
    a = ap.parse_args()

    with open(a.logfile, errors="replace") as f:
        alerts = analyze(read_zeek(f), a.min_queries, load_allowlist(a.allowlist))

    if a.json:
        print(json.dumps(alerts, indent=2))
        return 1 if alerts else 0
    if not alerts:
        print("No DNS tunneling found.")
        return 0

    print(f"[!] {len(alerts)} possible DNS tunnel(s) found\n")
    print(f"{'SEVERITY':<9} {'CLIENT':<15} {'DOMAIN':<22} {'QUERIES':>7}  REASONS")
    print("-" * 90)
    for x in alerts:
        print(f"{x['severity']:<9} {x['client']:<15} {x['domain']:<22} {x['queries']:>7}  "
              f"{'; '.join(x['reasons'])}")
        if x["decoded_sample"]:
            print(f"{'':<48}decoded: {x['decoded_sample']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
