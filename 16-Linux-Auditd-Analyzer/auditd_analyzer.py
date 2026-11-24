#!/usr/bin/env python3
"""Linux auditd log analyzer.

Reads /var/log/audit/audit.log, groups the lines into events and finds
reverse shells, encoded commands, programs run from temp folders, changes to
passwd/shadow/sudoers, new accounts, many denied accesses and audit tampering.
"""
import argparse
import collections
import json
import re
import sys

HEADER = re.compile(r"^type=(\w+) msg=audit\((\d+)\.\d+:(\d+)\):\s*(.*)$")
KV = re.compile(r'(\w+)=("[^"]*"|\S*)')

# Files that should only be changed by admin tools
WATCHED = {"/etc/passwd": "passwd", "/etc/shadow": "shadow", "/etc/sudoers": "sudoers",
           "/etc/ssh/sshd_config": "sshd_config"}
# Programs that are allowed to change those files
TRUSTED_EXE = ("/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/bin/passwd",
               "/usr/sbin/visudo", "/usr/bin/chage", "/usr/sbin/chpasswd")
TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")

# (name, regex on the full command line, MITRE ID)
CMD_RULES = [
    ("Reverse shell", re.compile(r"/dev/tcp/|\bnc(at)?\b.*\s-e\s|mkfifo.*\bnc\b|socat.*exec:", re.I), "T1059.004"),
    ("Encoded command", re.compile(r"base64\s+(-d|--decode).*\|\s*(ba)?sh|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64", re.I), "T1027"),
    ("Download and run", re.compile(r"(curl|wget)\s.*(\|\s*(ba)?sh|-O\s*/tmp/|-o\s*/tmp/)", re.I), "T1105"),
    ("Cron persistence", re.compile(r"crontab\s+-|/etc/cron", re.I), "T1053.003"),
]

SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def unquote(v):
    return v[1:-1] if len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v


def read_events(path):
    """Group audit lines by event id. Returns a list of event dicts."""
    events = collections.OrderedDict()
    with open(path, errors="replace") as f:
        for line in f:
            m = HEADER.match(line.strip())
            if not m:
                continue
            rtype, ts, eid, rest = m.groups()
            ev = events.setdefault(eid, {"id": eid, "time": int(ts), "records": []})
            fields = {k: unquote(v) for k, v in KV.findall(rest)}
            ev["records"].append((rtype, fields))
    return list(events.values())


def command_line(ev):
    """Join a0, a1, a2 ... of the EXECVE record into one string."""
    for rtype, f in ev["records"]:
        if rtype == "EXECVE":
            args = []
            i = 0
            while "a%d" % i in f:
                args.append(f["a%d" % i])
                i += 1
            return " ".join(args)
    return ""


def first(ev, rtype):
    for t, f in ev["records"]:
        if t == rtype:
            return f
    return {}


def analyze(events, denied_limit=5):
    alerts = []
    denied = collections.defaultdict(lambda: {"n": 0, "files": set()})

    def add(sev, kind, ev, who, detail, mitre):
        alerts.append({"severity": sev, "type": kind, "event": ev["id"], "user": who,
                       "detail": detail, "mitre": mitre})

    for ev in events:
        sc = first(ev, "SYSCALL")
        who = "auid=%s" % sc.get("auid", "?") if sc else "-"
        cmd = command_line(ev)
        exe = sc.get("exe", "")

        for rtype, f in ev["records"]:
            if rtype == "CONFIG_CHANGE" and ("audit_enabled=0" in str(f) or f.get("op") == "remove_rule"):
                add("HIGH", "Audit tampering", ev, "auid=%s" % f.get("auid", "?"),
                    "audit was turned off or a rule was removed", "T1562.001")
            if rtype in ("ADD_USER", "ADD_GROUP") and f.get("res") == "success":
                add("MEDIUM", "New account", ev, "auid=%s" % f.get("auid", "?"),
                    "%s %s" % (rtype, f.get("acct", "")), "T1136.001")

        if cmd:
            for name, rx, mitre in CMD_RULES:
                if rx.search(cmd):
                    add("HIGH" if name != "Cron persistence" else "MEDIUM", name, ev, who, cmd[:90], mitre)
                    break
            if exe.startswith(TEMP_DIRS) and sc.get("success") == "yes":
                add("HIGH", "Run from temp folder", ev, who, exe, "T1036")

        # writes to watched files by programs that are not admin tools
        for rtype, f in ev["records"]:
            if rtype == "PATH" and f.get("name") in WATCHED and f.get("nametype") in ("NORMAL", "CREATE", "DELETE"):
                if sc and sc.get("success") == "yes" and sc.get("key", "") in (
                        "identity", "sudoers", "sshd", "etc_write"):
                    if exe not in TRUSTED_EXE:
                        add("HIGH", "Sensitive file changed", ev, who,
                            "%s changed by %s" % (f["name"], exe or "?"), "T1098")

        # count denied file access by the same user
        if sc and sc.get("success") == "no" and sc.get("exit") in ("-13", "-1"):
            d = denied[sc.get("auid", "?")]
            d["n"] += 1
            for rtype, f in ev["records"]:
                if rtype == "PATH" and f.get("name"):
                    d["files"].add(f["name"])

    for auid, d in denied.items():
        if d["n"] >= denied_limit:
            alerts.append({"severity": "MEDIUM", "type": "Many denied accesses", "event": "-",
                           "user": "auid=%s" % auid, "mitre": "T1083",
                           "detail": "%d denied calls, %d different files" % (d["n"], len(d["files"]))})

    alerts.sort(key=lambda a: (SEV[a["severity"]], a["type"]))
    return alerts


def main():
    p = argparse.ArgumentParser(description="Analyze Linux auditd logs")
    p.add_argument("logfile")
    p.add_argument("-d", "--denied", type=int, default=5, help="denied calls before an alert (default 5)")
    p.add_argument("--json", action="store_true", help="print alerts as JSON")
    a = p.parse_args()

    events = read_events(a.logfile)
    alerts = analyze(events, a.denied)

    if a.json:
        print(json.dumps(alerts, indent=2))
    else:
        print("[*] %d audit events read" % len(events))
        if alerts:
            print("[!] %d alert(s) found\n" % len(alerts))
            print("%-9s %-22s %-8s %-11s %-10s %s" % ("SEVERITY", "TYPE", "EVENT", "USER", "MITRE", "DETAIL"))
            print("-" * 100)
            for x in alerts:
                print("%-9s %-22s %-8s %-11s %-10s %s" % (x["severity"], x["type"], x["event"], x["user"],
                                                          x["mitre"], x["detail"]))
        else:
            print("[+] nothing suspicious found")
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()
