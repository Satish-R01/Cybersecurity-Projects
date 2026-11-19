import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import dns_tunnel

ROOT = os.path.join(os.path.dirname(__file__), "..")
SAMPLE = os.path.join(ROOT, "samples", "dns.log")


def rec(query, client="10.10.1.5", qtype="A", rcode="NOERROR"):
    return {"id.orig_h": client, "query": query, "qtype_name": qtype, "rcode_name": rcode, "ts": "1"}


def test_base_domain():
    assert dns_tunnel.base_domain("www.google.com") == "google.com"
    assert dns_tunnel.base_domain("a.b.c.example.net.") == "example.net"
    assert dns_tunnel.base_domain("www.bbc.co.uk") == "bbc.co.uk"


def test_subdomain():
    assert dns_tunnel.subdomain("abc.x.evil.net", "evil.net") == "abc.x"
    assert dns_tunnel.subdomain("evil.net", "evil.net") == ""


def test_entropy():
    assert dns_tunnel.entropy("") == 0
    assert dns_tunnel.entropy("aaaa") == 0
    assert dns_tunnel.entropy("ab") == 1
    assert dns_tunnel.entropy("k3j9x2m7q8w1z5v4") > 3.5


def test_try_decode_hex():
    assert dns_tunnel.try_decode("70617373776f72643d313233.0001.x") == "password=123"
    assert dns_tunnel.try_decode("www") == ""
    assert dns_tunnel.try_decode("deadbeefdeadbeef") == ""


def test_read_zeek_tsv_and_json():
    tsv = ["#fields\tts\tid.orig_h\tquery\n", "1.0\t10.0.0.1\tgoogle.com\n", "#close\tx\n"]
    assert list(dns_tunnel.read_zeek(tsv))[0]["query"] == "google.com"
    js = ['{"ts": 1.0, "id.orig_h": "10.0.0.1", "query": "github.com"}\n']
    assert list(dns_tunnel.read_zeek(js))[0]["query"] == "github.com"


def test_normal_traffic_no_alert():
    recs = [rec("www.google.com") for _ in range(100)] + [rec(f"img{i % 3}.cdn.net") for i in range(50)]
    assert dns_tunnel.analyze(recs) == []


def test_tunnel_detected():
    import random
    random.seed(1)
    recs = [rec("".join(random.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(40)) + ".t.bad.info",
                qtype="TXT") for _ in range(30)]
    alerts = dns_tunnel.analyze(recs)
    assert len(alerts) == 1
    assert alerts[0]["domain"] == "bad.info"
    assert alerts[0]["severity"] == "HIGH"


def test_min_queries_and_allowlist():
    recs = [rec(f"{'ab12cd34ef56' * 4}{i}.bad.info", qtype="TXT") for i in range(10)]
    assert dns_tunnel.analyze(recs, min_queries=20) == []
    assert len(dns_tunnel.analyze(recs, min_queries=5)) == 1
    assert dns_tunnel.analyze(recs, min_queries=5, allowlist={"bad.info"}) == []


def test_sample_log():
    with open(SAMPLE) as f:
        alerts = dns_tunnel.analyze(dns_tunnel.read_zeek(f))
    found = {(a["client"], a["domain"]) for a in alerts}
    assert found == {("10.10.1.52", "cdn-update.info"), ("10.10.1.37", "data-sync-cdn.net")}
    exfil = [a for a in alerts if a["domain"] == "data-sync-cdn.net"][0]
    assert exfil["decoded_sample"].startswith("emp_id,name")


def test_cli_json_exit_code():
    p = subprocess.run([sys.executable, os.path.join(ROOT, "dns_tunnel.py"), SAMPLE, "--json"],
                       capture_output=True, text=True)
    assert p.returncode == 1
    assert len(json.loads(p.stdout)) == 2
