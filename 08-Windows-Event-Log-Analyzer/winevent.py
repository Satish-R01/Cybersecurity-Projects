#!/usr/bin/env python3
"""Windows Event Log analyzer.
Reads events exported as JSON lines and finds common attack signs."""
import argparse
import json
import sys
from collections import defaultdict

# Windows logon types I care about
REMOTE_TYPES = {"3", "10"}
SUSPICIOUS_PROC = {
    "mimikatz": "credential dumping tool",
    "-enc ": "encoded PowerShell",
    "-encodedcommand": "encoded PowerShell",
    "certutil": "certutil used to download or decode",
    "vssadmin delete shadows": "shadow copies deleted (ransomware sign)",
    "procdump": "procdump may be dumping lsass",
    "net user /add": "local user added from command line",
}
ADMIN_GROUPS = {"administrators", "domain admins", "remote desktop users"}


def load_events(path):
    """Read one JSON event per line. Bad lines are skipped."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def add(alerts, sev, rule, who, detail, mitre):
    alerts.append({"severity": sev, "rule": rule, "who": who,
                   "detail": detail, "mitre": mitre})


def analyze(events, fail_limit=5):
    alerts = []
    fails = defaultdict(list)  # ip -> list of (time, user)
    for e in events:
        eid = int(e.get("EventID", 0))
        d = e.get("Data", {})
        t = e.get("TimeCreated", "")
        ip = d.get("IpAddress", "-")
        if eid == 4625:
            fails[ip].append((t, d.get("TargetUserName", "?")))
        elif eid == 1102:
            add(alerts, "HIGH", "Audit log cleared", d.get("SubjectUserName", "?"),
                "Security log cleared at " + t, "T1070.001")
        elif eid == 4720:
            add(alerts, "MEDIUM", "User account created", d.get("TargetUserName", "?"),
                "created by %s at %s" % (d.get("SubjectUserName", "?"), t), "T1136.001")
        elif eid in (4728, 4732, 4756):
            grp = d.get("GroupName", "").lower()
            if grp in ADMIN_GROUPS:
                add(alerts, "HIGH", "Added to privileged group", d.get("MemberName", "?"),
                    "group %s by %s at %s" % (d.get("GroupName"), d.get("SubjectUserName", "?"), t),
                    "T1098")
        elif eid == 7045:
            path = d.get("ImagePath", "").lower()
            if "\\temp\\" in path or "\\users\\" in path or "cmd.exe" in path or "powershell" in path:
                add(alerts, "HIGH", "Suspicious new service", d.get("ServiceName", "?"),
                    "image path %s at %s" % (d.get("ImagePath"), t), "T1543.003")
        elif eid == 4688:
            cmd = d.get("CommandLine", "").lower()
            for key, why in SUSPICIOUS_PROC.items():
                if key in cmd:
                    add(alerts, "HIGH", "Suspicious process: " + why,
                        d.get("SubjectUserName", "?"), d.get("CommandLine", "")[:90], "T1059.001")
                    break

    # brute force and success after failures
    for ip, items in fails.items():
        users = {u for _, u in items}
        if len(items) >= fail_limit:
            sev = "HIGH" if len(users) >= 3 else "MEDIUM"
            add(alerts, sev, "Many failed logons", ip,
                "%d failures, %d account(s)" % (len(items), len(users)), "T1110")
            for e in events:
                d = e.get("Data", {})
                if (int(e.get("EventID", 0)) == 4624 and d.get("IpAddress") == ip
                        and d.get("LogonType") in REMOTE_TYPES
                        and e.get("TimeCreated", "") > items[-1][0]):
                    add(alerts, "HIGH", "Successful logon after failures", ip,
                        "user %s logged in at %s" % (d.get("TargetUserName"), e["TimeCreated"]),
                        "T1110")
                    break
    order = {"HIGH": 0, "MEDIUM": 1}
    alerts.sort(key=lambda a: order[a["severity"]])
    return alerts


def main():
    p = argparse.ArgumentParser(description="Windows Event Log analyzer")
    p.add_argument("logfile", help="events exported as JSON lines")
    p.add_argument("-f", "--fail-limit", type=int, default=5,
                   help="failed logons from one IP before alert (default 5)")
    p.add_argument("--json", action="store_true", help="print alerts as JSON")
    a = p.parse_args()
    alerts = analyze(load_events(a.logfile), a.fail_limit)
    if a.json:
        print(json.dumps(alerts, indent=2))
    elif alerts:
        print("[!] %d alert(s) found\n" % len(alerts))
        print("%-9s %-36s %-16s %s" % ("SEVERITY", "RULE", "WHO", "DETAIL"))
        print("-" * 100)
        for x in alerts:
            print("%-9s %-36s %-16s %s [%s]" % (x["severity"], x["rule"], x["who"][:16],
                                              x["detail"], x["mitre"]))
    else:
        print("No alerts.")
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
