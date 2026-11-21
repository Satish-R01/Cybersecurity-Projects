#!/usr/bin/env python3
"""Summarize Suricata eve.json alerts and find the noisy and dangerous ones."""
import argparse
import json
import sys
from collections import Counter, defaultdict

# category -> (MITRE technique, short note)
MITRE = {
    "web application attack": "T1190 Exploit Public-Facing Application",
    "a network trojan was detected": "T1071 Application Layer Protocol",
    "attempted administrator privilege gain": "T1210 Exploitation of Remote Services",
    "attempted information leak": "T1046 Network Service Discovery",
    "potentially bad traffic": "T1568 Dynamic Resolution",
}
SEV_NAME = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}


def parse_eve(lines):
    """Return only the alert events from eve.json lines. Bad lines are skipped."""
    alerts = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event_type") == "alert" and "alert" in e:
            alerts.append(e)
    return alerts


def summarize(alerts, min_count=10):
    sigs = Counter()
    sig_info = {}
    sources = defaultdict(Counter)
    targets = defaultdict(set)
    blocked = Counter()
    for e in alerts:
        a = e["alert"]
        sid = a.get("signature_id")
        sigs[sid] += 1
        sig_info[sid] = a
        sources[sid][e.get("src_ip", "?")] += 1
        targets[sid].add(e.get("dest_ip", "?"))
        if a.get("action") == "blocked":
            blocked[sid] += 1
    result = []
    for sid, count in sigs.most_common():
        a = sig_info[sid]
        sev = a.get("severity", 3)
        top_src, top_n = sources[sid].most_common(1)[0]
        notes = []
        if sev == 1:
            notes.append("high severity")
        if count >= min_count:
            notes.append("noisy (%d alerts)" % count)
        if len(sources[sid]) == 1 and count >= min_count:
            notes.append("one source only")
        if blocked[sid] == 0:
            notes.append("never blocked")
        result.append({
            "signature_id": sid,
            "signature": a.get("signature", ""),
            "category": a.get("category", ""),
            "severity": SEV_NAME.get(sev, "LOW"),
            "count": count,
            "top_source": top_src,
            "sources": len(sources[sid]),
            "targets": sorted(targets[sid]),
            "blocked": blocked[sid],
            "mitre": MITRE.get(a.get("category", "").lower(), "not mapped"),
            "notes": notes,
        })
    return result


def needs_attention(rows):
    """High severity alerts that were not blocked."""
    return [r for r in rows if r["severity"] == "HIGH" and r["blocked"] < r["count"]]


def main():
    p = argparse.ArgumentParser(description="Summarize Suricata eve.json alerts")
    p.add_argument("logfile")
    p.add_argument("-m", "--min-count", type=int, default=10, help="alerts needed to call a signature noisy")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args()
    with open(args.logfile, errors="replace") as f:
        alerts = parse_eve(f)
    rows = summarize(alerts, args.min_count)
    attention = needs_attention(rows)
    if args.json:
        print(json.dumps({"total_alerts": len(alerts), "signatures": rows}, indent=2))
    else:
        print("[*] %d alerts, %d signatures" % (len(alerts), len(rows)))
        print()
        print("%-8s %-6s %-17s %-44s %s" % ("SEVERITY", "COUNT", "TOP SOURCE", "SIGNATURE", "MITRE"))
        print("-" * 120)
        for r in rows:
            print("%-8s %-6d %-17s %-44s %s" % (r["severity"], r["count"], r["top_source"], r["signature"][:43], r["mitre"]))
        if attention:
            print()
            print("[!] %d high severity signature(s) not fully blocked:" % len(attention))
            for r in attention:
                print("    %s (%d alerts, %d blocked) -> %s" % (r["signature"], r["count"], r["blocked"], ", ".join(r["targets"])))
    return 1 if attention else 0


if __name__ == "__main__":
    sys.exit(main())
