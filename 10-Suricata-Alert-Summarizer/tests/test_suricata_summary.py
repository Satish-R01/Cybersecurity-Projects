import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import suricata_summary as s

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(HERE, "samples", "eve.json")


def alert(sid=1, sev=1, src="1.1.1.1", action="allowed", cat="Web Application Attack"):
    return json.dumps({"event_type": "alert", "src_ip": src, "dest_ip": "10.0.0.1",
                       "alert": {"signature_id": sid, "signature": "sig%d" % sid,
                                 "category": cat, "severity": sev, "action": action}})


def test_parse_skips_non_alerts_and_bad_lines():
    lines = ['{"event_type":"flow"}', "not json", "", alert()]
    assert len(s.parse_eve(lines)) == 1


def test_counts_and_top_source():
    rows = s.summarize(s.parse_eve([alert(src="a"), alert(src="a"), alert(src="b")]))
    assert rows[0]["count"] == 3 and rows[0]["top_source"] == "a" and rows[0]["sources"] == 2


def test_mitre_mapping_and_unmapped():
    rows = s.summarize(s.parse_eve([alert(1), alert(2, cat="Weird")]))
    by = {r["signature_id"]: r for r in rows}
    assert by[1]["mitre"].startswith("T1190")
    assert by[2]["mitre"] == "not mapped"


def test_noisy_note():
    rows = s.summarize(s.parse_eve([alert()] * 5), min_count=5)
    assert any("noisy" in n for n in rows[0]["notes"])


def test_attention_only_unblocked_high():
    rows = s.summarize(s.parse_eve([alert(1, action="blocked"), alert(2), alert(3, sev=3)]))
    att = s.needs_attention(rows)
    assert [r["signature_id"] for r in att] == [2]


def test_sample_file():
    with open(SAMPLE) as f:
        alerts = s.parse_eve(f)
    assert len(alerts) == 88
    rows = s.summarize(alerts)
    assert rows[0]["signature"].startswith("ET SCAN")
    assert len(s.needs_attention(rows)) == 3


def test_cli_json_exit_code():
    r = subprocess.run([sys.executable, os.path.join(HERE, "suricata_summary.py"), SAMPLE, "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 1
    assert json.loads(r.stdout)["total_alerts"] == 88
