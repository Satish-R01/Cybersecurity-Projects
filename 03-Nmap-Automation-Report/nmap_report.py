#!/usr/bin/env python3
"""Run an nmap scan (or read a saved nmap XML file) and make a CSV and HTML report."""
import argparse
import csv
import html
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

# open ports I want to look at first, with a short reason
RISKY = {
    21: "FTP sends passwords in clear text",
    23: "Telnet sends everything in clear text",
    69: "TFTP has no authentication",
    111: "rpcbind is exposed",
    135: "Windows RPC exposed",
    139: "NetBIOS exposed",
    445: "SMB exposed (check patching, EternalBlue style bugs)",
    512: "rexec, old and insecure",
    513: "rlogin, old and insecure",
    514: "rsh, old and insecure",
    1433: "MS SQL exposed",
    3306: "MySQL exposed",
    3389: "RDP exposed (brute force target)",
    5432: "PostgreSQL exposed",
    5900: "VNC exposed",
    6379: "Redis often has no password",
    27017: "MongoDB exposed",
}


def run_scan(target, out_file, extra_args):
    """Run nmap with service detection and save the XML."""
    if shutil.which("nmap") is None:
        sys.exit("nmap is not installed. Install it or use --xml with a saved scan.")
    cmd = ["nmap", "-sV", "-T4", "-oX", out_file] + extra_args + [target]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


def parse_xml(path):
    """Return a list of hosts, each with its open ports."""
    root = ET.parse(path).getroot()
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr")
        name_el = h.find("hostnames/hostname")
        name = name_el.get("name") if name_el is not None else ""
        os_el = h.find("os/osmatch")
        os_guess = os_el.get("name") if os_el is not None else ""

        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            svc = svc if svc is not None else ET.Element("service")
            port = int(p.get("portid"))
            version = " ".join(x for x in (svc.get("product"), svc.get("version")) if x)
            ports.append({
                "port": port,
                "proto": p.get("protocol"),
                "service": svc.get("name", ""),
                "version": version,
                "note": RISKY.get(port, ""),
            })
        hosts.append({"ip": ip, "name": name, "os": os_guess, "ports": ports})
    return hosts


def write_csv(hosts, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "hostname", "port", "proto", "service", "version", "note"])
        for h in hosts:
            for p in h["ports"]:
                w.writerow([h["ip"], h["name"], p["port"], p["proto"],
                            p["service"], p["version"], p["note"]])


def write_html(hosts, path):
    total = sum(len(h["ports"]) for h in hosts)
    risky = sum(1 for h in hosts for p in h["ports"] if p["note"])
    e = html.escape
    out = ["<!DOCTYPE html><html><head><meta charset='utf-8'><title>Nmap report</title>",
           "<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;margin-bottom:2em}"
           "td,th{border:1px solid #bbb;padding:4px 10px;text-align:left}th{background:#eee}"
           "tr.risky{background:#fde2e2}</style></head><body>",
           "<h1>Nmap scan report</h1>",
           f"<p>{len(hosts)} host(s) up, {total} open port(s), {risky} worth a closer look.</p>"]
    for h in hosts:
        title = h["ip"] + (f" ({h['name']})" if h["name"] else "")
        out.append(f"<h2>{e(title)}</h2>")
        if h["os"]:
            out.append(f"<p>OS guess: {e(h['os'])}</p>")
        out.append("<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Note</th></tr>")
        for p in h["ports"]:
            cls = " class='risky'" if p["note"] else ""
            out.append(f"<tr{cls}><td>{p['port']}/{p['proto']}</td><td>{e(p['service'])}</td>"
                       f"<td>{e(p['version'])}</td><td>{e(p['note'])}</td></tr>")
        out.append("</table>")
    out.append("</body></html>")
    with open(path, "w") as f:
        f.write("\n".join(out))


def print_summary(hosts):
    for h in hosts:
        title = h["ip"] + (f" ({h['name']})" if h["name"] else "")
        print(f"Host {title}  OS: {h['os'] or 'unknown'}")
        for p in h["ports"]:
            line = f"  {str(p['port']) + '/' + p['proto']:<10} {p['service']:<14} {p['version']}"
            if p["note"]:
                line += f"   <-- {p['note']}"
            print(line)
    total = sum(len(h["ports"]) for h in hosts)
    risky = sum(1 for h in hosts for p in h["ports"] if p["note"])
    print(f"\n{len(hosts)} host(s) up, {total} open port(s), {risky} flagged")


def main():
    ap = argparse.ArgumentParser(description="Nmap scan to CSV/HTML report")
    ap.add_argument("--target", help="host to scan (only scan what you are allowed to, e.g. scanme.nmap.org)")
    ap.add_argument("--xml", help="use an existing nmap -oX file instead of scanning")
    ap.add_argument("--save-xml", default="scan.xml", help="where to save the XML when scanning")
    ap.add_argument("--csv", default="report.csv")
    ap.add_argument("--html", default="report.html")
    ap.add_argument("--nmap-args", default="", help='extra nmap options, e.g. "-p 1-1000"')
    args = ap.parse_args()

    if not args.target and not args.xml:
        ap.error("give --target or --xml")
    xml_path = args.xml
    if not xml_path:
        run_scan(args.target, args.save_xml, args.nmap_args.split())
        xml_path = args.save_xml

    hosts = parse_xml(xml_path)
    print_summary(hosts)
    write_csv(hosts, args.csv)
    write_html(hosts, args.html)
    print(f"Wrote {args.csv} and {args.html}")


if __name__ == "__main__":
    main()
