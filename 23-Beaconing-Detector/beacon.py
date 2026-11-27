#!/usr/bin/env python3
"""Find C2 beaconing in proxy logs by looking for connections at regular intervals."""
import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime


def parse_time(value):
    """Accept epoch seconds or an ISO time like 2026-11-20T09:00:05."""
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value.replace("Z", "")).timestamp()


def read_log(path):
    """Read CSV with columns: time,src_ip,dst_host,dst_port,bytes_out,user_agent."""
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                rows.append({
                    "time": parse_time(r["time"]),
                    "src": r["src_ip"],
                    "dst": r["dst_host"].lower(),
                    "port": r.get("dst_port", ""),
                    "bytes": int(r.get("bytes_out") or 0),
                    "ua": r.get("user_agent", ""),
                })
            except (KeyError, ValueError):
                continue
    return rows


def load_allowlist(path):
    if not path:
        return set()
    with open(path) as f:
        return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}


def analyze_series(times, sizes):
    """Return stats for one src->dst pair, or None when it is too short."""
    times = sorted(times)
    gaps = [b - a for a, b in zip(times, times[1:])]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < 2:
        return None
    mean = statistics.mean(gaps)
    stdev = statistics.pstdev(gaps)
    cv = stdev / mean if mean else 1.0
    size_cv = 0.0
    if len(sizes) > 1 and statistics.mean(sizes) > 0:
        size_cv = statistics.pstdev(sizes) / statistics.mean(sizes)
    return {"count": len(times), "mean_gap": mean, "cv": cv, "size_cv": size_cv,
            "duration": times[-1] - times[0]}


def score(stats, min_conns, max_cv, ua_count):
    """Give points for every beacon sign. Returns (score, reasons)."""
    pts, why = 0, []
    if stats["count"] < min_conns:
        return 0, why
    if stats["cv"] <= max_cv:
        pts += 50
        why.append("regular interval (every ~%ds, jitter %.0f%%)" % (stats["mean_gap"], stats["cv"] * 100))
    elif stats["cv"] <= max_cv * 2.5:
        pts += 25
        why.append("fairly regular interval (every ~%ds, jitter %.0f%%)" % (stats["mean_gap"], stats["cv"] * 100))
    if pts and stats["size_cv"] <= 0.2:
        pts += 20
        why.append("same size every time")
    if pts and stats["duration"] >= 3600:
        pts += 15
        why.append("running for %.1f hours" % (stats["duration"] / 3600))
    if pts and ua_count == 1:
        pts += 5
        why.append("one user agent only")
    return pts, why


def detect(rows, min_conns=10, max_cv=0.2, allow=frozenset()):
    groups = defaultdict(list)
    for r in rows:
        if r["dst"] in allow:
            continue
        groups[(r["src"], r["dst"], r["port"])].append(r)
    alerts = []
    for (src, dst, port), items in groups.items():
        stats = analyze_series([i["time"] for i in items], [i["bytes"] for i in items])
        if not stats:
            continue
        pts, why = score(stats, min_conns, max_cv, len({i["ua"] for i in items}))
        if pts >= 50:
            alerts.append({"severity": "HIGH" if pts >= 80 else "MEDIUM", "score": pts,
                           "src": src, "dst": dst, "port": port, "connections": stats["count"],
                           "interval": round(stats["mean_gap"], 1), "reasons": why})
    return sorted(alerts, key=lambda a: -a["score"])


def main():
    p = argparse.ArgumentParser(description="Find beaconing in proxy logs")
    p.add_argument("logfile", help="CSV proxy log")
    p.add_argument("-m", "--min-conns", type=int, default=10, help="connections needed before a pair is checked")
    p.add_argument("-j", "--max-jitter", type=float, default=0.2, help="max jitter as a fraction of the interval")
    p.add_argument("-a", "--allowlist", help="file with trusted domains, one per line")
    p.add_argument("--json", action="store_true", help="print alerts as JSON")
    args = p.parse_args()

    alerts = detect(read_log(args.logfile), args.min_conns, args.max_jitter, load_allowlist(args.allowlist))
    if args.json:
        print(json.dumps(alerts, indent=2))
    elif alerts:
        print("[!] %d possible beacon(s) found\n" % len(alerts))
        print("%-9s %-13s %-24s %-5s %-6s %s" % ("SEVERITY", "SOURCE", "DESTINATION", "PORT", "CONNS", "REASONS"))
        print("-" * 100)
        for a in alerts:
            print("%-9s %-13s %-24s %-5s %-6d %s" % (a["severity"], a["src"], a["dst"], a["port"],
                                                   a["connections"], "; ".join(a["reasons"])))
    else:
        print("[+] No beaconing found")
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
