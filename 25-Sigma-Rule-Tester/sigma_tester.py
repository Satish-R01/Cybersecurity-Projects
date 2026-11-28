#!/usr/bin/env python3
"""Run simple Sigma rules against JSON log events and check the rules for missing fields."""
import argparse
import fnmatch
import json
import os
import re
import sys
from collections import defaultdict

import yaml

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------- reading rules and events ----------

def load_rules(path):
    """Read one .yml file or every .yml file in a folder."""
    files = []
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.endswith((".yml", ".yaml")):
                files.append(os.path.join(path, name))
    else:
        files.append(path)
    rules = []
    for fp in files:
        with open(fp) as f:
            try:
                for doc in yaml.safe_load_all(f):
                    if isinstance(doc, dict):
                        doc["_file"] = os.path.basename(fp)
                        rules.append(doc)
            except yaml.YAMLError as e:
                rules.append({"_file": os.path.basename(fp), "_error": str(e).splitlines()[0]})
    return rules


def load_events(path):
    """Read JSON lines. Bad lines are skipped."""
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict):
                events.append(ev)
    return events


# ---------- matching one field ----------

def wildcard_to_regex(value):
    """Sigma * and ? wildcards.
    \\* means a normal star, and two backslashes before a wildcard mean one real backslash then the wildcard."""
    out, i = "", 0
    while i < len(value):
        c = value[i]
        if value.startswith("\\\\", i) and i + 2 < len(value) and value[i + 2] in "*?":
            out += re.escape("\\")
            i += 2
            continue
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?":
            out += re.escape(value[i + 1])
            i += 2
            continue
        if c == "*":
            out += ".*"
        elif c == "?":
            out += "."
        else:
            out += re.escape(c)
        i += 1
    return out


def get_field(event, name):
    if name in event:
        return event[name]
    lower = {k.lower(): v for k, v in event.items()}
    return lower.get(name.lower())


def match_value(actual, pattern, mods):
    """Check one event value against one rule value. Always case-insensitive."""
    if pattern is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    a, p = str(actual), str(pattern)
    if "re" in mods:
        try:
            return re.search(p, a, re.IGNORECASE | re.DOTALL) is not None
        except re.error:
            return False
    if "contains" in mods:
        return p.lower() in a.lower()
    if "startswith" in mods:
        return a.lower().startswith(p.lower())
    if "endswith" in mods:
        return a.lower().endswith(p.lower())
    return re.fullmatch(wildcard_to_regex(p), a, re.IGNORECASE | re.DOTALL) is not None


def match_field(event, key, expected):
    """key can look like CommandLine|contains|all."""
    parts = key.split("|")
    name, mods = parts[0], set(parts[1:])
    values = expected if isinstance(expected, list) else [expected]
    actual = get_field(event, name)
    results = [match_value(actual, v, mods) for v in values]
    return all(results) if "all" in mods else any(results)


def match_selection(event, sel):
    """A map means AND between fields. A list of maps means OR. A list of words is a keyword search."""
    if isinstance(sel, dict):
        return all(match_field(event, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        text = json.dumps(event).lower()
        for item in sel:
            if isinstance(item, dict):
                if match_selection(event, item):
                    return True
            elif str(item).lower() in text:
                return True
        return False
    return False


# ---------- condition parser ----------

class ConditionError(Exception):
    pass


def tokenize(cond):
    return re.findall(r"\(|\)|[^\s()]+", cond)


class Parser:
    """and / or / not, brackets, '1 of selection*', 'all of them'."""

    def __init__(self, cond, names):
        self.tokens = tokenize(cond)
        self.pos = 0
        self.names = names

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise ConditionError("unexpected '%s' in condition" % self.peek())
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() and self.peek().lower() == "or":
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek() and self.peek().lower() == "and":
            self.take()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.peek() and self.peek().lower() == "not":
            self.take()
            return ("not", self.parse_not())
        return self.parse_atom()

    def parse_atom(self):
        tok = self.take()
        if tok is None:
            raise ConditionError("condition ended too early")
        if tok == "(":
            node = self.parse_or()
            if self.take() != ")":
                raise ConditionError("missing closing bracket")
            return node
        if tok.lower() in ("1", "all") and self.peek() and self.peek().lower() == "of":
            self.take()
            target = self.take()
            if target is None:
                raise ConditionError("'of' needs a target")
            if target.lower() == "them":
                chosen = list(self.names)
            else:
                chosen = [n for n in self.names if fnmatch.fnmatch(n, target)]
            if not chosen:
                raise ConditionError("no selection matches '%s'" % target)
            return ("all" if tok.lower() == "all" else "any", chosen)
        if tok not in self.names:
            raise ConditionError("unknown selection '%s'" % tok)
        return ("sel", tok)


def eval_node(node, results):
    kind = node[0]
    if kind == "sel":
        return results[node[1]]
    if kind == "not":
        return not eval_node(node[1], results)
    if kind == "and":
        return eval_node(node[1], results) and eval_node(node[2], results)
    if kind == "or":
        return eval_node(node[1], results) or eval_node(node[2], results)
    if kind == "all":
        return all(results[n] for n in node[1])
    if kind == "any":
        return any(results[n] for n in node[1])
    return False


def compile_rule(rule):
    """Return (tree, selections) or raise ConditionError when the rule cannot be run."""
    det = rule.get("detection")
    if not isinstance(det, dict):
        raise ConditionError("no detection section")
    cond = det.get("condition")
    if isinstance(cond, list):
        cond = " or ".join("(%s)" % c for c in cond)
    if not cond:
        raise ConditionError("no condition")
    if "|" in str(cond):
        raise ConditionError("aggregation conditions (count, near) are not supported")
    sels = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}
    tree = Parser(str(cond), list(sels)).parse()
    return tree, sels


def rule_matches(compiled, event):
    tree, sels = compiled
    results = {name: match_selection(event, sel) for name, sel in sels.items()}
    return eval_node(tree, results)


# ---------- rule checks ----------

def lint_rule(rule):
    """Return a list of problems with the rule file itself."""
    issues = []
    for field in ("title", "id", "status", "description", "logsource", "detection", "level"):
        if not rule.get(field):
            issues.append("missing %s" % field)
    level = str(rule.get("level", "")).lower()
    if level and level not in VALID_LEVELS:
        issues.append("level '%s' is not valid" % level)
    tags = rule.get("tags") or []
    if not any(str(t).lower().startswith("attack.t") for t in tags):
        issues.append("no MITRE ATT&CK technique tag")
    if not rule.get("falsepositives"):
        issues.append("no falsepositives listed")
    det = rule.get("detection") or {}
    if isinstance(det, dict):
        for name, sel in det.items():
            if name == "condition":
                continue
            if sel in ({}, [], None):
                issues.append("selection '%s' is empty" % name)
        for name, sel in det.items():
            if isinstance(sel, dict):
                for key, val in sel.items():
                    if key.split("|")[0].lower() in ("commandline", "image") and val in ("*", ["*"]):
                        issues.append("'%s' matches everything" % key)
    return issues


def technique_ids(rule):
    return sorted({str(t)[7:].upper() for t in (rule.get("tags") or []) if str(t).lower().startswith("attack.t")})


# ---------- running everything ----------

def run(rules, events, min_level="informational", lint=True):
    report = {"rules": [], "skipped": [], "events": len(events)}
    floor = LEVEL_ORDER.get(min_level, 0)
    for rule in rules:
        title = rule.get("title") or rule.get("_file")
        if "_error" in rule:
            report["skipped"].append({"file": rule["_file"], "reason": "bad YAML: " + rule["_error"]})
            continue
        try:
            compiled = compile_rule(rule)
        except ConditionError as e:
            report["skipped"].append({"file": rule["_file"], "reason": str(e)})
            continue
        level = str(rule.get("level", "medium")).lower()
        if LEVEL_ORDER.get(level, 2) < floor:
            continue
        hits = [i for i, ev in enumerate(events) if rule_matches(compiled, ev)]
        report["rules"].append({
            "file": rule["_file"], "title": title, "id": rule.get("id", ""), "level": level,
            "techniques": technique_ids(rule), "hits": len(hits), "event_numbers": [h + 1 for h in hits],
            "examples": [{"event_number": h + 1, "event": events[h]} for h in hits[:3]],
            "issues": lint_rule(rule) if lint else [],
        })
    return report


def short(event, width=110):
    text = event.get("CommandLine") or event.get("Image") or json.dumps(event)
    return text if len(text) <= width else text[:width - 3] + "..."


def print_report(report):
    total = sum(r["hits"] for r in report["rules"])
    fired = [r for r in report["rules"] if r["hits"]]
    quiet = [r for r in report["rules"] if not r["hits"]]
    print("[*] %d rules, %d events" % (len(report["rules"]), report["events"]))
    if fired:
        print("[!] %d rule(s) matched, %d alerts in total\n" % (len(fired), total))
        print("%-9s %-5s %-44s %s" % ("LEVEL", "HITS", "RULE", "ATT&CK"))
        print("-" * 80)
        for r in sorted(fired, key=lambda x: (-LEVEL_ORDER.get(x["level"], 0), -x["hits"])):
            print("%-9s %-5d %-44s %s" % (r["level"].upper(), r["hits"], r["title"][:44], ", ".join(r["techniques"])))
            for ex in r["examples"]:
                host = ex["event"].get("Computer", "?")
                print("    event %-4d %-12s %s" % (ex["event_number"], host, short(ex["event"])))
    else:
        print("[+] No rule matched")
    if quiet:
        print("\nRules with no matches: " + ", ".join(r["title"] for r in quiet))
    issues = [r for r in report["rules"] if r["issues"]]
    if issues:
        print("\nRule problems:")
        for r in issues:
            print("  %s: %s" % (r["file"], "; ".join(r["issues"])))
    for s in report["skipped"]:
        print("[-] skipped %s: %s" % (s["file"], s["reason"]))


def main():
    p = argparse.ArgumentParser(description="Test Sigma rules against JSON log events")
    p.add_argument("rules", help="a Sigma .yml file or a folder of them")
    p.add_argument("events", help="JSON lines file with events")
    p.add_argument("-l", "--min-level", default="informational", choices=sorted(VALID_LEVELS),
                   help="only run rules at this level or higher")
    p.add_argument("--no-lint", action="store_true", help="do not check the rule files")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    args = p.parse_args()

    report = run(load_rules(args.rules), load_events(args.events), args.min_level, not args.no_lint)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 1 if any(r["hits"] for r in report["rules"]) else 0


if __name__ == "__main__":
    sys.exit(main())
