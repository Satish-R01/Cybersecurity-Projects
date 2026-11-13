import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from detector import parse_log, analyze

LOG = os.path.join(os.path.dirname(__file__), "..", "sample_logs", "auth.log")

def run():
    with open(LOG) as f:
        fails, succ = parse_log(f, 2026)
    return {a["ip"]: a for a in analyze(fails, succ, threshold=5, window_min=10)}

def test_detects_root_bruteforce():
    a = run()["45.83.12.7"]
    assert a["failed_attempts"] == 25 and a["severity"] == "HIGH"

def test_detects_spraying():
    assert run()["103.21.44.9"]["technique"].startswith("T1110.003")

def test_flags_compromise():
    a = run()["185.220.101.3"]
    assert a["severity"] == "CRITICAL" and a["success_after_failures"]

def test_ignores_normal_and_slow():
    a = run()
    assert "192.168.1.10" not in a and "91.10.1.1" not in a
