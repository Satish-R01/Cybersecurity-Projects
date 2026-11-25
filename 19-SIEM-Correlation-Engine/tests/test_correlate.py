import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import correlate

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(os.path.dirname(HERE), "samples")


def ev(t, **k):
    e = {"time": "2024-05-14T" + t + "Z"}
    e.update(k)
    e["_ts"] = correlate.parse_time(e["time"])
    return e


RULE = {"name": "r", "severity": "HIGH", "group_by": "ip", "window_seconds": 60,
        "steps": [{"event": "a", "min_count": 2}, {"event": "b"}]}


def test_sequence_in_window():
    events = [ev("10:00:00", event="a", ip="1"), ev("10:00:10", event="a", ip="1"),
              ev("10:00:20", event="b", ip="1")]
    assert len(correlate.run_rule(RULE, events)) == 1


def test_outside_window():
    events = [ev("10:00:00", event="a", ip="1"), ev("10:00:10", event="a", ip="1"),
              ev("10:05:00", event="b", ip="1")]
    assert correlate.run_rule(RULE, events) == []


def test_different_keys_do_not_mix():
    events = [ev("10:00:00", event="a", ip="1"), ev("10:00:10", event="a", ip="2"),
              ev("10:00:20", event="b", ip="1")]
    assert correlate.run_rule(RULE, events) == []


def test_wrong_order():
    events = [ev("10:00:00", event="b", ip="1"), ev("10:00:10", event="a", ip="1"),
              ev("10:00:20", event="a", ip="1")]
    assert correlate.run_rule(RULE, events) == []


def test_match_field():
    rule = {"name": "r", "severity": "LOW", "group_by": "h", "window_seconds": 60,
            "steps": [{"event": "g", "match": {"group": "Administrators"}}]}
    assert correlate.run_rule(rule, [ev("10:00:00", event="g", h="x", group="Users")]) == []
    assert len(correlate.run_rule(rule, [ev("10:00:00", event="g", h="x", group="Administrators")])) == 1


def test_sample_files():
    events = correlate.load_events(os.path.join(SAMPLES, "events.jsonl"))
    rules = correlate.load_rules(os.path.join(SAMPLES, "rules.json"))
    alerts = correlate.correlate(events, rules)
    found = {(a["rule"], a["value"]) for a in alerts}
    assert found == {
        ("Brute force then success", "203.0.113.45"),
        ("New user made admin", "svc_backup2"),
        ("Download then execute", "WS-12"),
        ("VPN login then data upload", "ravi"),
    }


def test_cli_json_exit_code():
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), "correlate.py"),
                        os.path.join(SAMPLES, "events.jsonl"), "-r",
                        os.path.join(SAMPLES, "rules.json"), "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 1
    assert len(json.loads(r.stdout)) == 4
