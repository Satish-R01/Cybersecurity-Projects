import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import arp_detector as a

SAMPLES = os.path.join(HERE, "samples")
GW_MAC = "3c:52:82:4a:10:01"
BAD_MAC = "00:0c:29:7f:c1:66"


def write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def req(src_mac, target, sender):
    return ("10:00:00.000001 %s > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: "
            "Request who-has %s tell %s, length 28" % (src_mac, target, sender))


def rep(frame_mac, ip, mac, dst="00:0c:29:5e:7a:10"):
    return ("10:00:01.000001 %s > %s, ethertype ARP (0x0806), length 42: "
            "Reply %s is-at %s, length 28" % (frame_mac, dst, ip, mac))


def types(alerts):
    return sorted(x["type"] for x in alerts)


def test_norm_mac():
    assert a.norm_mac("3C-52-82-4A-10-01") == GW_MAC


def test_parse_capture_request_and_reply(tmp_path):
    p = write(tmp_path, "cap.txt", [req("00:0c:29:5e:7a:10", "192.168.1.1", "192.168.1.10"),
                                    rep(GW_MAC, "192.168.1.1", GW_MAC)])
    pk = a.parse_capture(p)
    assert pk[0]["op"] == "request" and pk[0]["target"] == "192.168.1.1"
    assert pk[1]["op"] == "reply" and pk[1]["mac"] == GW_MAC


def test_parse_capture_without_e_flag(tmp_path):
    p = write(tmp_path, "cap.txt", ["10:00:01.1 ARP, Reply 192.168.1.1 is-at 3c:52:82:4a:10:01, length 28"])
    pk = a.parse_capture(p)
    assert pk[0]["src_mac"] is None and pk[0]["mac"] == GW_MAC


def test_normal_traffic_has_no_alerts(tmp_path):
    p = write(tmp_path, "cap.txt", [req("00:0c:29:5e:7a:10", "192.168.1.1", "192.168.1.10"),
                                    rep(GW_MAC, "192.168.1.1", GW_MAC)] * 5)
    assert a.analyze_capture(a.parse_capture(p), {"192.168.1.1": GW_MAC}) == []


def test_trusted_gateway_mac_changed(tmp_path):
    p = write(tmp_path, "cap.txt", [rep(BAD_MAC, "192.168.1.1", BAD_MAC)])
    alerts = a.analyze_capture(a.parse_capture(p), {"192.168.1.1": GW_MAC})
    assert "Trusted IP MAC changed" in types(alerts)


def test_unsolicited_replies(tmp_path):
    p = write(tmp_path, "cap.txt", [rep(BAD_MAC, "192.168.1.1", BAD_MAC)] * 5)
    assert "Unsolicited replies" in types(a.analyze_capture(a.parse_capture(p), {}))


def test_answered_requests_are_not_unsolicited(tmp_path):
    lines = []
    for _ in range(6):
        lines += [req("00:0c:29:5e:7a:10", "192.168.1.1", "192.168.1.10"), rep(GW_MAC, "192.168.1.1", GW_MAC)]
    p = write(tmp_path, "cap.txt", lines)
    assert "Unsolicited replies" not in types(a.analyze_capture(a.parse_capture(p), {}))


def test_mac_mismatch(tmp_path):
    p = write(tmp_path, "cap.txt", [rep(BAD_MAC, "192.168.1.40", "b8:27:eb:6c:20:40")])
    assert "MAC mismatch" in types(a.analyze_capture(a.parse_capture(p), {}))


def test_one_mac_many_ips(tmp_path):
    p = write(tmp_path, "cap.txt", [rep(BAD_MAC, "192.168.1.%d" % i, BAD_MAC) for i in (1, 23, 40)])
    assert "One MAC for many IPs" in types(a.analyze_capture(a.parse_capture(p), {}))


def test_arp_scan(tmp_path):
    p = write(tmp_path, "cap.txt", [req("52:54:00:12:aa:80", "192.168.1.%d" % i, "192.168.1.80")
                                    for i in range(100, 125)])
    alerts = a.analyze_capture(a.parse_capture(p), {})
    assert types(alerts) == ["ARP scan"]
    assert alerts[0]["mitre"] == "T1018"


def test_sample_capture():
    trusted = a.load_trusted(os.path.join(SAMPLES, "trusted.txt"))
    alerts = a.analyze_capture(a.parse_capture(os.path.join(SAMPLES, "arp_capture.txt")), trusted)
    assert types(alerts) == ["ARP scan", "IP-MAC conflict", "MAC mismatch", "One MAC for many IPs",
                             "Trusted IP MAC changed", "Unsolicited replies"]
    assert alerts[0]["severity"] == "HIGH"


def test_linux_table_with_poisoned_gateway():
    trusted = a.load_trusted(os.path.join(SAMPLES, "trusted.txt"))
    rows = a.parse_table(os.path.join(SAMPLES, "arp_table.txt"))
    assert len(rows) == 4  # broadcast entry skipped
    assert types(a.analyze_table(rows, trusted)) == ["One MAC for many IPs", "Trusted IP MAC changed"]


def test_windows_clean_table():
    trusted = a.load_trusted(os.path.join(SAMPLES, "trusted.txt"))
    rows = a.parse_table(os.path.join(SAMPLES, "arp_table_clean.txt"))
    assert ("192.168.1.1", GW_MAC) in rows
    assert a.analyze_table(rows, trusted) == []


def test_cli_json_and_exit_code():
    r = subprocess.run([sys.executable, os.path.join(HERE, "arp_detector.py"),
                        os.path.join(SAMPLES, "arp_capture.txt"), "--json"], capture_output=True, text=True)
    assert r.returncode == 1
    assert len(json.loads(r.stdout)) >= 5


def test_cli_clean_exit_zero():
    r = subprocess.run([sys.executable, os.path.join(HERE, "arp_detector.py"), "--table",
                        os.path.join(SAMPLES, "arp_table_clean.txt"),
                        "-t", os.path.join(SAMPLES, "trusted.txt")], capture_output=True, text=True)
    assert r.returncode == 0
    assert "no ARP spoofing signs" in r.stdout
