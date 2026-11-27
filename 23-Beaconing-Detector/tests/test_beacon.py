import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import beacon

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(HERE, "samples", "proxy.csv")
ALLOW = os.path.join(HERE, "samples", "allowlist.txt")


def make_rows(times, dst="evil.test", size=200):
    return [{"time": t, "src": "10.0.0.5", "dst": dst, "port": "443", "bytes": size, "ua": "x"} for t in times]


def test_parse_time_epoch_and_iso():
    assert beacon.parse_time("100") == 100.0
    assert beacon.parse_time("2026-11-20T00:00:00") < beacon.parse_time("2026-11-20T00:01:00")


def test_regular_series_has_low_cv():
    s = beacon.analyze_series([0, 60, 120, 180, 240], [100] * 5)
    assert s["cv"] == 0 and s["mean_gap"] == 60


def test_too_short_series_is_ignored():
    assert beacon.analyze_series([0, 60], [1, 1]) is None


def test_detects_regular_beacon():
    alerts = beacon.detect(make_rows(range(0, 1200, 60)))
    assert len(alerts) == 1 and alerts[0]["interval"] == 60


def test_random_traffic_not_flagged():
    times = [0, 5, 400, 410, 1500, 1503, 4000, 4100, 9000, 9001, 9500, 12000]
    assert beacon.detect(make_rows(times)) == []


def test_allowlist_skips_domain():
    rows = make_rows(range(0, 1200, 60), dst="time.windows.com")
    assert beacon.detect(rows, allow={"time.windows.com"}) == []


def test_min_conns_respected():
    assert beacon.detect(make_rows(range(0, 360, 60))) == []
    assert len(beacon.detect(make_rows(range(0, 360, 60)), min_conns=5)) == 1


def test_sample_file():
    alerts = beacon.detect(beacon.read_log(SAMPLE), allow=beacon.load_allowlist(ALLOW))
    assert {a["dst"] for a in alerts} == {"update-check.cloudsvc-api.net", "cdn.static-assets-hub.com"}


def test_cli_json_exit_code():
    r = subprocess.run([sys.executable, os.path.join(HERE, "beacon.py"), SAMPLE, "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 1
    assert len(json.loads(r.stdout)) >= 2
