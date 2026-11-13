#!/usr/bin/env python3
"""
Brute-Force Login Detector
Parses Linux SSH auth logs (/var/log/auth.log style), finds IPs with repeated
failed logins inside a time window, flags successful logins after failures
(possible compromise), and maps findings to MITRE ATT&CK T1110.
Author: Satish R
"""
import argparse, csv, json, re, sys
from collections import defaultdict
from datetime import datetime, timedelta

FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Failed password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
INVALID_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Invalid user "
    r"(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
SUCCESS_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Accepted \S+ for "
    r"(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


def parse_ts(ts, year):
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_log(lines, year):
    failures, successes = defaultdict(list), defaultdict(list)
    for line in lines:
        m = FAILED_RE.search(line)
        if m:
            failures[m["ip"]].append((parse_ts(m["ts"], year), m["user"]))
            continue
        m = SUCCESS_RE.search(line)
        if m:
            successes[m["ip"]].append((parse_ts(m["ts"], year), m["user"]))
    return failures, successes


def max_in_window(times, window):
    """Largest number of failures inside any sliding window."""
    times = sorted(times)
    best, start = 0, 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def severity(count, compromised):
    if compromised:
        return "CRITICAL"
    if count >= 20:
        return "HIGH"
    if count >= 10:
        return "MEDIUM"
    return "LOW"


def analyze(failures, successes, threshold, window_min):
    window = timedelta(minutes=window_min)
    alerts = []
    for ip, events in failures.items():
        times = [t for t, _ in events]
        peak = max_in_window(times, window)
        if peak < threshold:
            continue
        users = sorted({u for _, u in events})
        last_fail = max(times)
        after = [(t, u) for t, u in successes.get(ip, []) if t >= min(times)]
        compromised = bool(after)
        alerts.append({
            "ip": ip,
            "failed_attempts": len(events),
            "peak_in_window": peak,
            "users_targeted": users,
            "first_seen": min(times).isoformat(sep=" "),
            "last_seen": last_fail.isoformat(sep=" "),
            "success_after_failures": [f"{u} @ {t.isoformat(sep=' ')}" for t, u in after],
            "technique": "T1110.001 Password Guessing" if len(users) <= 2 else "T1110.003 Password Spraying",
            "severity": severity(len(events), compromised),
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(alerts, key=lambda a: (order[a["severity"]], -a["failed_attempts"]))


def print_report(alerts):
    if not alerts:
        print("[+] No brute-force activity detected.")
        return
    print(f"[!] {len(alerts)} suspicious IP(s) found\n")
    print(f"{'SEVERITY':<9} {'IP':<16} {'FAILS':>5} {'PEAK':>5}  TECHNIQUE")
    print("-" * 70)
    for a in alerts:
        print(f"{a['severity']:<9} {a['ip']:<16} {a['failed_attempts']:>5} {a['peak_in_window']:>5}  {a['technique']}")
        print(f"          users: {', '.join(a['users_targeted'][:6])}")
        for s in a["success_after_failures"]:
            print(f"          !!! SUCCESSFUL LOGIN AFTER FAILURES: {s}")
    print("\nRecommended: block CRITICAL/HIGH IPs (e.g. sudo ufw deny from <ip>), reset passwords of")
    print("compromised accounts, enable key-based SSH auth and fail2ban.")


def main():
    p = argparse.ArgumentParser(description="Detect SSH brute-force attacks in auth logs")
    p.add_argument("logfile", help="path to auth.log ('-' for stdin)")
    p.add_argument("-t", "--threshold", type=int, default=5, help="failed attempts to alert on (default 5)")
    p.add_argument("-w", "--window", type=int, default=10, help="time window in minutes (default 10)")
    p.add_argument("-y", "--year", type=int, default=datetime.now().year, help="log year (syslog has none)")
    p.add_argument("--json", help="write alerts to a JSON file")
    p.add_argument("--csv", help="write alerts to a CSV file")
    a = p.parse_args()

    fh = sys.stdin if a.logfile == "-" else open(a.logfile, encoding="utf-8", errors="ignore")
    with fh:
        failures, successes = parse_log(fh, a.year)
    alerts = analyze(failures, successes, a.threshold, a.window)
    print_report(alerts)

    if a.json:
        with open(a.json, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"\n[+] JSON report: {a.json}")
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["severity", "ip", "failed_attempts", "peak_in_window", "users_targeted",
                        "first_seen", "last_seen", "success_after_failures", "technique"])
            for x in alerts:
                w.writerow([x["severity"], x["ip"], x["failed_attempts"], x["peak_in_window"],
                            ";".join(x["users_targeted"]), x["first_seen"], x["last_seen"],
                            ";".join(x["success_after_failures"]), x["technique"]])
        print(f"[+] CSV report: {a.csv}")
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()
