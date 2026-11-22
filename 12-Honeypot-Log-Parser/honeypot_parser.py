#!/usr/bin/env python3
"""Reads a Cowrie (SSH honeypot) JSON log and summarizes what attackers did."""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict

# command patterns I treat as suspicious, with the MITRE technique
PATTERNS = [
    (r"\b(wget|curl|tftp|ftpget)\b", "Downloads a file", "T1105 Ingress Tool Transfer"),
    (r"chmod\s+\+?[0-9x]+", "Makes a file executable", "T1222 File Permissions Modification"),
    (r"authorized_keys", "Adds an SSH key", "T1098.004 SSH Authorized Keys"),
    (r"xmrig|minerd|stratum\+tcp|\| *bash", "Miner or piped shell", "T1496 Resource Hijacking"),
    (r"crontab|/etc/cron", "Touches cron", "T1053.003 Cron"),
    (r"history -c|unset HISTFILE|rm .*\.log", "Hides its tracks", "T1070 Indicator Removal"),
    (r"uname|/proc/cpuinfo|nproc|whoami", "Looks around the system", "T1082 System Information Discovery"),
]


def parse_log(lines):
    """Return a list of event dicts, skipping blank and bad lines."""
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and "eventid" in e:
            events.append(e)
    return events


def classify_command(cmd):
    hits = []
    for pattern, label, mitre in PATTERNS:
        if re.search(pattern, cmd, re.I):
            hits.append((label, mitre))
    return hits


def analyze(events, min_failures=10):
    sessions = defaultdict(lambda: {"ip": "", "failed": 0, "success": None,
                                    "commands": [], "downloads": []})
    creds = Counter()
    for e in events:
        s = sessions[e.get("session", "?")]
        s["ip"] = e.get("src_ip", s["ip"])
        eid = e["eventid"]
        if eid == "cowrie.login.failed":
            s["failed"] += 1
            creds[(e.get("username", ""), e.get("password", ""))] += 1
        elif eid == "cowrie.login.success":
            s["success"] = (e.get("username", ""), e.get("password", ""))
            creds[s["success"]] += 1
        elif eid == "cowrie.command.input":
            s["commands"].append(e.get("input", ""))
        elif eid == "cowrie.session.file_download":
            s["downloads"].append({"url": e.get("url", ""), "sha256": e.get("shasum", "")})

    per_ip = defaultdict(lambda: {"sessions": 0, "failed": 0})
    for s in sessions.values():
        per_ip[s["ip"]]["sessions"] += 1
        per_ip[s["ip"]]["failed"] += s["failed"]

    findings = []
    for ip, d in per_ip.items():
        if d["failed"] >= min_failures:
            findings.append({"type": "brute_force", "ip": ip, "severity": "MEDIUM",
                             "detail": "%d failed logins in %d sessions" % (d["failed"], d["sessions"]),
                             "mitre": "T1110 Brute Force"})
        elif d["sessions"] >= min_failures and d["failed"] == 0:
            findings.append({"type": "scanner", "ip": ip, "severity": "LOW",
                             "detail": "%d sessions with no login attempt" % d["sessions"],
                             "mitre": "T1046 Network Service Discovery"})

    for sid, s in sessions.items():
        if not s["success"]:
            continue
        flags = []
        for c in s["commands"]:
            for label, mitre in classify_command(c):
                if (label, mitre) not in flags:
                    flags.append((label, mitre))
        serious = [f for f in flags if f[0] != "Looks around the system"]
        findings.append({
            "type": "compromised_session" if serious or s["downloads"] else "login_only",
            "ip": s["ip"], "session": sid,
            "severity": "HIGH" if serious or s["downloads"] else "LOW",
            "detail": "logged in as %s/%s, %d commands" % (s["success"][0], s["success"][1], len(s["commands"])),
            "behaviour": [f[0] for f in flags],
            "mitre": ", ".join(sorted({f[1] for f in flags})),
            "downloads": s["downloads"],
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order[f["severity"]])
    return {"sessions": len(sessions), "ips": len(per_ip),
            "top_credentials": [{"user": u, "password": p, "count": c} for (u, p), c in creds.most_common(5)],
            "findings": findings}


def print_report(r):
    print("[*] %d sessions from %d IPs" % (r["sessions"], r["ips"]))
    print("\nTop credentials tried:")
    for c in r["top_credentials"]:
        print("    %-8s %-10s %d" % (c["user"], c["password"], c["count"]))
    print("\n%-8s %-15s %s" % ("SEVERITY", "IP", "FINDING"))
    print("-" * 90)
    for f in r["findings"]:
        print("%-8s %-15s %s: %s" % (f["severity"], f["ip"], f["type"], f["detail"]))
        if f.get("behaviour"):
            print("%25s%s" % ("", "behaviour: " + ", ".join(f["behaviour"])))
        for d in f.get("downloads", []):
            print("%25sdownload: %s sha256=%s" % ("", d["url"], d["sha256"][:16] + "..."))
        if f["mitre"]:
            print("%25sMITRE: %s" % ("", f["mitre"]))
    high = [f for f in r["findings"] if f["severity"] == "HIGH"]
    if high:
        print("\n[!] %d attacker(s) got in and ran commands" % len(high))


def main():
    p = argparse.ArgumentParser(description="Summarize a Cowrie honeypot JSON log")
    p.add_argument("logfile")
    p.add_argument("-m", "--min-failures", type=int, default=10,
                   help="failed logins (or sessions) to call an IP noisy, default 10")
    p.add_argument("--json", action="store_true", help="print JSON")
    a = p.parse_args()
    try:
        with open(a.logfile, errors="replace") as f:
            events = parse_log(f)
    except OSError as err:
        print("Cannot read file: %s" % err, file=sys.stderr)
        return 2
    r = analyze(events, a.min_failures)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print_report(r)
    return 1 if r["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
