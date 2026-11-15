import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from nmap_report import parse_xml, write_csv, write_html

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "scanme.xml")


def test_down_host_is_skipped():
    hosts = parse_xml(SAMPLE)
    assert [h["ip"] for h in hosts] == ["45.33.32.156", "192.168.56.20"]


def test_only_open_ports_are_listed():
    hosts = parse_xml(SAMPLE)
    ports = [p["port"] for p in hosts[0]["ports"]]
    assert ports == [22, 80, 9929, 31337]
    assert 443 not in ports


def test_service_version_and_hostname():
    h = parse_xml(SAMPLE)[0]
    assert h["name"] == "scanme.nmap.org"
    assert h["ports"][0]["version"] == "OpenSSH 6.6.1p1 Ubuntu"


def test_risky_ports_get_a_note():
    h = parse_xml(SAMPLE)[1]
    notes = {p["port"]: p["note"] for p in h["ports"]}
    assert "clear text" in notes[23]
    assert notes[3389] != "" and notes[445] != ""


def test_csv_report(tmp_path):
    out = tmp_path / "r.csv"
    write_csv(parse_xml(SAMPLE), str(out))
    rows = list(csv.DictReader(open(out)))
    assert len(rows) == 9
    assert rows[0]["host"] == "45.33.32.156" and rows[0]["port"] == "22"


def test_html_report(tmp_path):
    out = tmp_path / "r.html"
    write_html(parse_xml(SAMPLE), str(out))
    text = open(out).read()
    assert "scanme.nmap.org" in text and "class='risky'" in text


def test_run_scan_builds_command(monkeypatch):
    import nmap_report
    seen = {}
    monkeypatch.setattr(nmap_report.shutil, "which", lambda x: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_report.subprocess, "run", lambda cmd, **kw: seen.update(cmd=cmd))
    nmap_report.run_scan("scanme.nmap.org", "out.xml", ["-p", "1-100"])
    assert seen["cmd"] == ["nmap", "-sV", "-T4", "-oX", "out.xml", "-p", "1-100", "scanme.nmap.org"]
