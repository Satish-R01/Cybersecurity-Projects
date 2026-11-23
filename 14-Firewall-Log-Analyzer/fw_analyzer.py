#!/usr/bin/env python3
"""Firewall log analyzer.

Reads iptables / UFW kernel log lines and finds port scans, host sweeps,
repeated hits on sensitive ports and blocked outbound beaconing.
"""
import argparse
import collections
import json
import re
import sys

# Ports that should never be open to the internet
SENSITIVE = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL", 5900: "VNC"}

KV = re.compile(r"(\w+)=(\S*)")
TIME = re.compile(r"^(\w{3}\s+\d+\s[\d:]{8})")


def parse_line(line):
    """Return a dict for one firewall log line, or None if it is not one."""
    if "SRC=" not in line or "DST=" not in line:
        return None
    fields = dict(KV.findall(line))
    m = TIME.match(line)
    if "BLOCK" in line or "DROP" in line or "REJECT" in line:
        action = "BLOCK"
    elif "ALLOW" in line or "ACCEPT" in line:
        action = "ALLOW"
    else:
        action = "OTHER"
    try:
        dpt = int(fields.get("DPT", 0))
    except ValueError:
        dpt = 0
    return {
        "time": m.group(1) if m else "",
        "action": action,
        "src": fields["SRC"],
        "dst": fields["DST"],
        "proto": fields.get("PROTO", ""),
        "dpt": dpt,
        "outbound": bool(fields.get("OUT")),
    }


def read_events(path):
    events = []
    with open(path, errors="replace") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                events.append(ev)
    return events


def analyze(events, scan_ports=15, sweep_hosts=10, hits=10, beacon=8):
    alerts = []
    blocked_in = [e for e in events if e["action"] == "BLOCK" and not e["outbound"]]

    # one source, many destination ports on one host
    pairs = collections.defaultdict(set)
    for e in blocked_in:
        pairs[(e["src"], e["dst"])].add(e["dpt"])
    for (src, dst), ports in pairs.items():
        if len(ports) >= scan_ports:
            alerts.append({"type": "Port scan", "severity": "HIGH", "src": src, "target": dst,
                           "count": len(ports), "detail": "%d different ports on one host" % len(ports),
                           "mitre": "T1046"})

    # one source, same port on many hosts
    sweep = collections.defaultdict(set)
    for e in blocked_in:
        sweep[(e["src"], e["dpt"])].add(e["dst"])
    for (src, port), hosts in sweep.items():
        if len(hosts) >= sweep_hosts:
            alerts.append({"type": "Host sweep", "severity": "MEDIUM", "src": src, "target": "port %d" % port,
                           "count": len(hosts), "detail": "port %d tried on %d hosts" % (port, len(hosts)),
                           "mitre": "T1046"})

    # repeated blocked hits on sensitive ports (skip sources already seen as scanners)
    scanners = {a["src"] for a in alerts}
    counts = collections.Counter((e["src"], e["dpt"]) for e in blocked_in if e["dpt"] in SENSITIVE)
    for (src, port), n in counts.items():
        if n >= hits and src not in scanners:
            alerts.append({"type": "Sensitive port hits", "severity": "MEDIUM", "src": src,
                           "target": "%s (%d)" % (SENSITIVE[port], port), "count": n,
                           "detail": "%d blocked attempts on %s" % (n, SENSITIVE[port]),
                           "mitre": "T1110" if port in (22, 3389, 23) else "T1021"})

    # internal host keeps trying to reach the same outside ip:port and gets blocked
    out = collections.Counter((e["src"], e["dst"], e["dpt"]) for e in events
                              if e["action"] == "BLOCK" and e["outbound"])
    for (src, dst, port), n in out.items():
        if n >= beacon:
            alerts.append({"type": "Blocked outbound beacon", "severity": "HIGH", "src": src,
                           "target": "%s:%d" % (dst, port), "count": n,
                           "detail": "%d blocked tries to the same outside address" % n,
                           "mitre": "T1071"})

    order = {"HIGH": 0, "MEDIUM": 1}
    alerts.sort(key=lambda a: (order[a["severity"]], -a["count"]))
    return alerts


def main():
    p = argparse.ArgumentParser(description="Analyze iptables/UFW firewall logs")
    p.add_argument("logfile")
    p.add_argument("-p", "--scan-ports", type=int, default=15, help="distinct ports for a port scan (default 15)")
    p.add_argument("-s", "--sweep-hosts", type=int, default=10, help="distinct hosts for a sweep (default 10)")
    p.add_argument("-n", "--hits", type=int, default=10, help="hits on a sensitive port (default 10)")
    p.add_argument("-b", "--beacon", type=int, default=8, help="blocked outbound tries (default 8)")
    p.add_argument("--json", action="store_true", help="print alerts as JSON")
    a = p.parse_args()

    events = read_events(a.logfile)
    alerts = analyze(events, a.scan_ports, a.sweep_hosts, a.hits, a.beacon)

    if a.json:
        print(json.dumps(alerts, indent=2))
    else:
        blocked = sum(1 for e in events if e["action"] == "BLOCK")
        print("[*] %d firewall events read, %d blocked" % (len(events), blocked))
        if alerts:
            print("[!] %d alert(s) found\n" % len(alerts))
            print("%-9s %-24s %-16s %-20s %5s  %s" % ("SEVERITY", "TYPE", "SOURCE", "TARGET", "COUNT", "MITRE"))
            print("-" * 86)
            for x in alerts:
                print("%-9s %-24s %-16s %-20s %5d  %s" % (x["severity"], x["type"], x["src"], x["target"],
                                                          x["count"], x["mitre"]))
        else:
            print("[+] nothing suspicious found")
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()
