#!/usr/bin/env python3
"""Small SIEM correlation engine.

Reads normalized events (JSON lines) and a rules file (JSON).
A rule is a list of steps that must happen in order, for the same
key (like src_ip or user), inside a time window.
"""
import argparse
import json
import sys
from datetime import datetime


def parse_time(value):
    # accepts 2024-05-14T10:02:11Z style times
    return datetime.strptime(value.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z").timestamp()


def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                e["_ts"] = parse_time(e["time"])
            except (ValueError, KeyError):
                continue  # skip bad lines
            events.append(e)
    events.sort(key=lambda e: e["_ts"])
    return events


def load_rules(path):
    with open(path) as f:
        return json.load(f)


def step_matches(step, event):
    if event.get("event") != step["event"]:
        return False
    for key, want in step.get("match", {}).items():
        if event.get(key) != want:
            return False
    return True


def run_rule(rule, events):
    """Return a list of alerts for one rule."""
    alerts = []
    key = rule["group_by"]
    window = rule["window_seconds"]
    steps = rule["steps"]
    groups = {}
    for e in events:
        if key in e:
            groups.setdefault(e[key], []).append(e)

    for value, evs in groups.items():
        i = 0
        matched = []
        start = None
        for e in evs:
            if start is not None and e["_ts"] - start > window:
                # window is over, start again
                i, matched, start = 0, [], None
            step = steps[i]
            if step_matches(step, e):
                if start is None:
                    start = e["_ts"]
                matched.append(e)
                need = step.get("min_count", 1)
                e["_hit"] = i
                step_hits = [m for m in matched if m.get("_hit") == i]
                if len(step_hits) >= need:
                    i += 1
                    if i == len(steps):
                        alerts.append(make_alert(rule, value, matched))
                        i, matched, start = 0, [], None
    return alerts


def make_alert(rule, value, matched):
    return {
        "rule": rule["name"],
        "severity": rule["severity"],
        "mitre": rule.get("mitre", ""),
        "key": rule["group_by"],
        "value": value,
        "first": matched[0]["time"],
        "last": matched[-1]["time"],
        "events": len(matched),
        "summary": rule.get("description", ""),
    }


def correlate(events, rules):
    # clear marks from older runs
    for e in events:
        e.pop("_hit", None)
    alerts = []
    for rule in rules:
        for e in events:
            e.pop("_hit", None)
        alerts.extend(run_rule(rule, events))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: (order.get(a["severity"], 3), a["first"]))
    return alerts


def main():
    p = argparse.ArgumentParser(description="Simple SIEM correlation engine")
    p.add_argument("events", help="events file, one JSON object per line")
    p.add_argument("-r", "--rules", default="samples/rules.json", help="rules file")
    p.add_argument("--json", action="store_true", help="print alerts as JSON")
    args = p.parse_args()

    events = load_events(args.events)
    rules = load_rules(args.rules)
    alerts = correlate(events, rules)

    if args.json:
        print(json.dumps(alerts, indent=2))
    elif alerts:
        print("[!] %d correlated alert(s) from %d events\n" % (len(alerts), len(events)))
        print("%-8s %-28s %-16s %-6s %s" % ("SEVERITY", "RULE", "KEY", "EVENTS", "FIRST -> LAST"))
        print("-" * 100)
        for a in alerts:
            print("%-8s %-28s %-16s %-6d %s -> %s" % (
                a["severity"], a["rule"], a["value"], a["events"], a["first"], a["last"]))
            print("         %s (%s)" % (a["summary"], a["mitre"]))
    else:
        print("No correlated alerts in %d events." % len(events))
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
