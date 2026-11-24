#!/usr/bin/env python3
"""ARP spoofing detector.

Reads saved ARP traffic (tcpdump -n -e arp output) or an ARP table (arp -a)
and finds ARP spoofing: gateway MAC changes, one MAC claiming many IPs,
IP to MAC flip-flops, unsolicited replies, MAC mismatches and ARP scans.
"""
import argparse
import collections
import json
import re
import sys

MAC = r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}"
IP = r"\d{1,3}(?:\.\d{1,3}){3}"

# tcpdump line with -e (ethernet header shown)
ETH = re.compile(r"^(\S+)\s+(" + MAC + r")\s+>\s+(" + MAC + r")")
REQ = re.compile(r"Request who-has (" + IP + r")(?: \(\S+\))? tell (" + IP + r")")
REPLY = re.compile(r"Reply (" + IP + r") is-at (" + MAC + r")")
TIME = re.compile(r"^(\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)")

# arp -a lines. Linux: ? (192.168.1.1) at aa:bb:.. [ether] on eth0
# Windows: 192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic
TABLE_LINUX = re.compile(r"\((" + IP + r")\) at (" + MAC + r")")
TABLE_WIN = re.compile(r"^\s*(" + IP + r")\s+(" + MAC + r")\s+(\w+)")

BROADCAST = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def norm_mac(mac):
    """Make MACs look the same: lower case with colons."""
    return mac.lower().replace("-", ":")


def load_trusted(path):
    """Read 'ip mac' pairs I know are correct, like the real gateway."""
    trusted = {}
    if not path:
        return trusted
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            ip, mac = line.split()[:2]
            trusted[ip] = norm_mac(mac)
    return trusted


def parse_capture(path):
    """Read tcpdump ARP output. Returns a list of packet dicts."""
    packets = []
    with open(path, errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if "ARP" not in line and "who-has" not in line and "is-at" not in line:
                continue
            pkt = {"line": n, "time": "", "src_mac": None, "dst_mac": None}
            t = TIME.match(line)
            if t:
                pkt["time"] = t.group(1)
            e = ETH.match(line)
            if e:
                pkt["src_mac"] = norm_mac(e.group(2))
                pkt["dst_mac"] = norm_mac(e.group(3))
            r = REPLY.search(line)
            q = REQ.search(line)
            if r:
                pkt.update(op="reply", ip=r.group(1), mac=norm_mac(r.group(2)))
            elif q:
                pkt.update(op="request", target=q.group(1), ip=q.group(2), mac=pkt["src_mac"])
            else:
                continue
            packets.append(pkt)
    return packets


def parse_table(path):
    """Read arp -a output. Returns a list of (ip, mac)."""
    rows = []
    with open(path, errors="replace") as f:
        for line in f:
            m = TABLE_LINUX.search(line) or TABLE_WIN.match(line)
            if m:
                mac = norm_mac(m.group(2))
                # skip broadcast and multicast entries, they are normal
                if mac not in BROADCAST and not mac.startswith("01:00:5e"):
                    rows.append((m.group(1), mac))
    return rows


def alert(sev, kind, ip, mac, detail, mitre="T1557.002"):
    return {"severity": sev, "type": kind, "ip": ip, "mac": mac, "mitre": mitre, "detail": detail}


def check_pairs(pairs, trusted, max_ips):
    """Checks that work on both captures and tables. pairs = list of (ip, mac)."""
    alerts = []
    ip_macs = collections.OrderedDict()
    mac_ips = collections.OrderedDict()
    for ip, mac in pairs:
        if not mac or mac in BROADCAST:
            continue
        ip_macs.setdefault(ip, [])
        if mac not in ip_macs[ip]:
            ip_macs[ip].append(mac)
        mac_ips.setdefault(mac, [])
        if ip not in mac_ips[mac]:
            mac_ips[mac].append(ip)

    # A trusted IP (like the gateway) showing a MAC that is not the real one
    for ip, real in trusted.items():
        for mac in ip_macs.get(ip, []):
            if mac != real:
                alerts.append(alert("HIGH", "Trusted IP MAC changed", ip, mac,
                                    "expected %s, seen %s" % (real, mac)))

    # One IP seen with two or more MACs
    for ip, macs in ip_macs.items():
        if len(macs) > 1 and ip not in trusted:
            alerts.append(alert("MEDIUM", "IP-MAC conflict", ip, macs[-1],
                                "%d MACs for one IP: %s" % (len(macs), ", ".join(macs))))

    # One MAC answering for many IPs (attacker poisoning several hosts)
    for mac, ips in mac_ips.items():
        if len(ips) >= max_ips:
            alerts.append(alert("HIGH", "One MAC for many IPs", ips[0], mac,
                                "%d IPs point to this MAC: %s" % (len(ips), ", ".join(ips[:5]))))
    return alerts


def analyze_capture(packets, trusted, max_ips=3, max_unsolicited=5, scan_limit=20):
    """Run all checks on a list of ARP packets."""
    pairs = []
    pending = collections.Counter()           # requests not answered yet, by IP
    unsolicited = collections.Counter()
    requests_by_src = collections.defaultdict(set)
    alerts = []

    for p in packets:
        if p["op"] == "request":
            pending[p["target"]] += 1
            requests_by_src[(p["ip"], p["mac"])].add(p["target"])
            if p["mac"]:
                pairs.append((p["ip"], p["mac"]))
            continue
        pairs.append((p["ip"], p["mac"]))
        # Reply that nobody asked for (gratuitous or poisoning)
        if pending[p["ip"]] > 0:
            pending[p["ip"]] -= 1
        else:
            unsolicited[p["mac"]] += 1
        # Ethernet sender is not the MAC inside the ARP reply
        if p["src_mac"] and p["src_mac"] != p["mac"]:
            alerts.append(alert("HIGH", "MAC mismatch", p["ip"], p["src_mac"],
                                "frame from %s but ARP says %s (line %d)" % (p["src_mac"], p["mac"], p["line"])))

    alerts += check_pairs(pairs, trusted, max_ips)

    for mac, count in unsolicited.items():
        if count >= max_unsolicited:
            alerts.append(alert("MEDIUM", "Unsolicited replies", "-", mac,
                                "%d replies nobody asked for" % count))

    for (ip, mac), targets in requests_by_src.items():
        if len(targets) >= scan_limit:
            alerts.append(alert("LOW", "ARP scan", ip, mac or "-",
                                "asked for %d different IPs" % len(targets), mitre="T1018"))

    alerts.sort(key=lambda a: (SEV[a["severity"]], a["type"], a["ip"]))
    return alerts


def analyze_table(rows, trusted, max_ips=2):
    """Checks for one arp -a snapshot."""
    # In a table, even two IPs with the same MAC is odd, so the limit is 2 here
    alerts = check_pairs(rows, trusted, max_ips)
    alerts.sort(key=lambda a: (SEV[a["severity"]], a["type"], a["ip"]))
    return alerts


def print_alerts(alerts, count_line):
    print(count_line)
    if not alerts:
        print("[+] no ARP spoofing signs found")
        return
    print("[!] %d alert(s) found\n" % len(alerts))
    print("%-9s %-23s %-16s %-19s %-10s %s" % ("SEVERITY", "TYPE", "IP", "MAC", "MITRE", "DETAIL"))
    print("-" * 110)
    for a in alerts:
        ip = a["ip"] if len(a["ip"]) <= 16 else a["ip"][:13] + "..."
        mac = a["mac"] if len(a["mac"]) <= 19 else a["mac"][:16] + "..."
        print("%-9s %-23s %-16s %-19s %-10s %s" % (a["severity"], a["type"], ip, mac, a["mitre"], a["detail"]))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find ARP spoofing in saved ARP traffic or an ARP table")
    ap.add_argument("file", help="tcpdump -n -e arp output, or arp -a output with --table")
    ap.add_argument("--table", action="store_true", help="file is arp -a output")
    ap.add_argument("-t", "--trusted", help="file with 'ip mac' pairs that are known good")
    ap.add_argument("-m", "--max-ips", type=int, help="IPs for one MAC before an alert (default 3, or 2 with --table)")
    ap.add_argument("-u", "--unsolicited", type=int, default=5, help="unsolicited replies before an alert (default 5)")
    ap.add_argument("-s", "--scan", type=int, default=20, help="different IPs asked before ARP scan alert (default 20)")
    ap.add_argument("--json", action="store_true", help="print alerts as JSON")
    args = ap.parse_args(argv)

    trusted = load_trusted(args.trusted)
    if args.table:
        rows = parse_table(args.file)
        alerts = analyze_table(rows, trusted, args.max_ips or 2)
        count_line = "[*] %d ARP table entries read" % len(rows)
    else:
        packets = parse_capture(args.file)
        alerts = analyze_capture(packets, trusted, args.max_ips or 3, args.unsolicited, args.scan)
        count_line = "[*] %d ARP packets read" % len(packets)

    if args.json:
        print(json.dumps(alerts, indent=2))
    else:
        print_alerts(alerts, count_line)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
