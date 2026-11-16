#!/usr/bin/env python3
"""Simple file integrity monitor: SHA-256 baseline and change check."""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(directory):
    result = {}
    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            if os.path.islink(path):
                continue
            try:
                st = os.stat(path)
                result[os.path.relpath(path, directory)] = {
                    "sha256": sha256(path),
                    "size": st.st_size,
                    "mode": oct(st.st_mode & 0o777),
                }
            except OSError as e:
                print("skip %s: %s" % (path, e), file=sys.stderr)
    return result


def compare(old, new):
    changes = []
    for p in sorted(set(old) | set(new)):
        if p not in old:
            changes.append(("NEW", p))
        elif p not in new:
            changes.append(("DELETED", p))
        elif old[p]["sha256"] != new[p]["sha256"]:
            changes.append(("MODIFIED", p))
        elif old[p]["mode"] != new[p]["mode"]:
            changes.append(("PERMISSION", p))
    return changes


def main():
    ap = argparse.ArgumentParser(description="File integrity monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline", help="create baseline")
    b.add_argument("directory")
    b.add_argument("-o", "--output", default="baseline.json")
    c = sub.add_parser("check", help="compare directory with baseline")
    c.add_argument("directory")
    c.add_argument("-b", "--baseline", default="baseline.json")
    args = ap.parse_args()

    if args.cmd == "baseline":
        data = scan(args.directory)
        with open(args.output, "w") as f:
            json.dump({"created": datetime.now().isoformat(timespec="seconds"),
                       "files": data}, f, indent=2)
        print("Baseline saved: %d files -> %s" % (len(data), args.output))
        return 0

    with open(args.baseline) as f:
        old = json.load(f)["files"]
    changes = compare(old, scan(args.directory))
    if not changes:
        print("OK: no changes")
        return 0
    print("[!] %d change(s) found" % len(changes))
    for kind, p in changes:
        print("%-11s %s" % (kind, p))
    return 1


if __name__ == "__main__":
    sys.exit(main())
