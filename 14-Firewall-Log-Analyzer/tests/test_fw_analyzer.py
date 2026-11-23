import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import fw_analyzer as fw

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "ufw.log")
SCRIPT = os.path.join(os.path.dirname(__file__), "..", "fw_analyzer.py")

LINE = ("Nov 20 10:05:01 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.7 "
        "DST=10.0.0.10 LEN=60 TTL=50 ID=1 PROTO=TCP SPT=40000 DPT=22 WINDOW=1024 SYN")


def ev(src, dst, port, action="BLOCK", out=False):
    return {"time": "", "action": action, "src": src, "dst": dst, "proto": "TCP", "dpt": port, "outbound": out}


def test_parse_line():
    e = fw.parse_line(LINE)
    assert e["src"] == "203.0.113.7" and e["dpt"] == 22 and e["action"] == "BLOCK"
    assert e["outbound"] is False and e["time"] == "Nov 20 10:05:01"


def test_parse_ignores_other_lines():
    assert fw.parse_line("Nov 20 10:00:00 fw01 sshd[1]: hello") is None


def test_outbound_flag():
    e = fw.parse_line(LINE.replace("IN=eth0 OUT=", "IN= OUT=eth0"))
    assert e["outbound"] is True


def test_port_scan():
    events = [ev("1.2.3.4", "10.0.0.1", p) for p in range(100, 120)]
    assert fw.analyze(events)[0]["type"] == "Port scan"


def test_below_threshold_is_quiet():
    events = [ev("1.2.3.4", "10.0.0.1", p) for p in range(100, 105)]
    assert fw.analyze(events) == []


def test_sweep():
    events = [ev("1.2.3.4", "10.0.0.%d" % i, 445) for i in range(1, 15)]
    assert any(a["type"] == "Host sweep" for a in fw.analyze(events))


def test_allowed_traffic_not_counted():
    events = [ev("1.2.3.4", "10.0.0.1", p, action="ALLOW") for p in range(100, 130)]
    assert fw.analyze(events) == []


def test_beacon():
    events = [ev("10.0.0.5", "8.8.4.4", 4444, out=True) for _ in range(10)]
    a = fw.analyze(events)
    assert a[0]["type"] == "Blocked outbound beacon" and a[0]["severity"] == "HIGH"


def test_sample_file():
    types = {(a["type"], a["src"]) for a in fw.analyze(fw.read_events(SAMPLE))}
    assert ("Port scan", "203.0.113.7") in types
    assert ("Host sweep", "198.51.100.23") in types
    assert ("Sensitive port hits", "192.0.2.88") in types
    assert ("Blocked outbound beacon", "10.0.0.55") in types
    assert not any(s == "198.51.100.77" for _, s in types)


def test_cli_json_exit_code():
    r = subprocess.run([sys.executable, SCRIPT, SAMPLE, "--json"], capture_output=True, text=True)
    assert r.returncode == 1
    assert len(json.loads(r.stdout)) == 4
