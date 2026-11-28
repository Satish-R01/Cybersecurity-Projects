import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sigma_tester as st

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(HERE, "samples", "rules")
EVENTS = os.path.join(HERE, "samples", "events.jsonl")


def make_rule(detection, **extra):
    rule = {"title": "t", "id": "1", "status": "test", "description": "d", "level": "high",
            "logsource": {"product": "windows"}, "tags": ["attack.t1059"],
            "falsepositives": ["none"], "detection": detection}
    rule.update(extra)
    return rule


def hits(detection, event):
    return st.rule_matches(st.compile_rule(make_rule(detection)), event)


# --- field matching ---

def test_exact_match_is_case_insensitive():
    assert st.match_value("CMD.EXE", "cmd.exe", set())


def test_wildcards():
    assert st.match_value("C:\\Temp\\a.exe", "C:\\Temp\\\\*.exe", set())
    assert not st.match_value("C:\\Temp\\a.dll", "C:\\Temp\\\\*.exe", set())
    assert st.match_value("a*c", "a\\*c", set())
    assert not st.match_value("abc", "a\\*c", set())
    assert st.match_value("abc", "a?c", set())


def test_contains_startswith_endswith():
    assert st.match_value("powershell -enc AAA", " -enc ", {"contains"})
    assert st.match_value("C:\\x\\a.exe", "a.exe", {"endswith"})
    assert not st.match_value("C:\\x\\a.exe", "x", {"startswith"})
    assert st.match_value("C:\\x\\a.exe", "C:\\x", {"startswith"})


def test_regex_modifier():
    assert st.match_value("net user /domain", r"net\s+user\s.*/domain", {"re"})
    assert not st.match_value("net user", r"/domain$", {"re"})


def test_all_modifier_needs_every_value():
    ev = {"CommandLine": "vssadmin delete shadows"}
    assert st.match_field(ev, "CommandLine|contains|all", ["delete", "shadows"])
    assert not st.match_field(ev, "CommandLine|contains|all", ["delete", "catalog"])
    assert st.match_field(ev, "CommandLine|contains", ["catalog", "shadows"])


def test_missing_field_does_not_match_and_null_matches_missing():
    assert not st.match_field({}, "Image|endswith", "x.exe")
    assert st.match_field({}, "Image", None)
    assert not st.match_field({"Image": "a"}, "Image", None)


def test_field_name_is_not_case_sensitive():
    assert st.match_field({"commandline": "abc"}, "CommandLine|contains", "abc")


def test_keyword_selection_and_list_of_maps():
    ev = {"CommandLine": "Mimikatz sekurlsa"}
    assert st.match_selection(ev, ["mimikatz"])
    assert st.match_selection(ev, [{"Image": "x"}, {"CommandLine|contains": "sekurlsa"}])
    assert not st.match_selection(ev, ["nothing here"])


# --- conditions ---

def test_and_or_not():
    det = {"a": {"x": "1"}, "b": {"y": "2"}, "condition": "a and not b"}
    assert hits(det, {"x": "1", "y": "9"})
    assert not hits(det, {"x": "1", "y": "2"})
    det["condition"] = "a or b"
    assert hits(det, {"y": "2"})


def test_brackets_change_order():
    det = {"a": {"x": "1"}, "b": {"y": "2"}, "c": {"z": "3"}, "condition": "a and (b or c)"}
    assert hits(det, {"x": "1", "z": "3"})
    assert not hits(det, {"x": "0", "y": "2"})


def test_one_of_and_all_of():
    det = {"sel_a": {"x": "1"}, "sel_b": {"y": "2"}, "condition": "1 of sel_*"}
    assert hits(det, {"y": "2"})
    det["condition"] = "all of sel_*"
    assert not hits(det, {"y": "2"})
    assert hits(det, {"x": "1", "y": "2"})
    det["condition"] = "all of them"
    assert hits(det, {"x": "1", "y": "2"})


def test_bad_conditions_raise():
    for cond in ("a and", "unknown_name", "(a", "1 of nothing_*", "a b"):
        with pytest.raises(st.ConditionError):
            st.compile_rule(make_rule({"a": {"x": "1"}, "condition": cond}))


def test_aggregation_condition_is_not_supported():
    with pytest.raises(st.ConditionError):
        st.compile_rule(make_rule({"a": {"x": "1"}, "condition": "a | count() > 5"}))


def test_condition_list_is_or():
    det = {"a": {"x": "1"}, "b": {"y": "2"}, "condition": ["a", "b"]}
    assert hits(det, {"y": "2"})


# --- rule checks ---

def test_good_rule_has_no_issues():
    assert st.lint_rule(make_rule({"a": {"x": "1"}, "condition": "a"})) == []


def test_lint_finds_problems():
    rule = make_rule({"a": {}, "condition": "a"}, level="severe", tags=[], falsepositives=[])
    text = "; ".join(st.lint_rule(rule))
    assert "level 'severe'" in text
    assert "no MITRE ATT&CK technique tag" in text
    assert "no falsepositives" in text
    assert "selection 'a' is empty" in text


def test_lint_finds_match_everything():
    rule = make_rule({"a": {"Image": "*"}, "condition": "a"})
    assert any("matches everything" in i for i in st.lint_rule(rule))


def test_technique_ids():
    rule = make_rule({}, tags=["attack.execution", "attack.t1059.001", "attack.t1204"])
    assert st.technique_ids(rule) == ["T1059.001", "T1204"]


# --- files ---

def test_load_events_skips_bad_lines(tmp_path):
    f = tmp_path / "e.jsonl"
    f.write_text('{"a": 1}\nnot json\n\n[1,2]\n{"b": 2}\n')
    assert st.load_events(str(f)) == [{"a": 1}, {"b": 2}]


def test_bad_yaml_is_reported_not_crashed(tmp_path):
    (tmp_path / "broken.yml").write_text("title: [unclosed\n")
    report = st.run(st.load_rules(str(tmp_path)), [])
    assert report["skipped"] and "bad YAML" in report["skipped"][0]["reason"]


def test_sample_rules_and_events():
    report = st.run(st.load_rules(RULES), st.load_events(EVENTS))
    by_title = {r["title"]: r for r in report["rules"]}
    assert report["events"] == 88
    assert by_title["Shadow Copies Deleted"]["hits"] == 2
    assert by_title["Encoded PowerShell Command"]["hits"] == 2
    assert by_title["Office App Starts Command Shell"]["hits"] == 2
    assert by_title["Certutil Used To Download A File"]["hits"] == 1
    assert by_title["Account And Domain Discovery Commands"]["hits"] == 3
    assert by_title["Suspicious Mimikatz Name"]["hits"] == 0
    assert any(s["file"] == "unsupported_count_rule.yml" for s in report["skipped"])


def test_filter_removes_system_task():
    # the schtasks run by SYSTEM on the file server must not alert
    report = st.run(st.load_rules(RULES), st.load_events(EVENTS))
    rule = [r for r in report["rules"] if r["title"].startswith("Scheduled Task")][0]
    assert rule["hits"] == 1
    assert rule["examples"][0]["event"]["Computer"] == "WS-HR-01"


def test_min_level_hides_low_rules():
    report = st.run(st.load_rules(RULES), st.load_events(EVENTS), min_level="high")
    assert {r["level"] for r in report["rules"]} <= {"high", "critical"}


def test_cli_json_and_exit_code():
    res = subprocess.run([sys.executable, os.path.join(HERE, "sigma_tester.py"), RULES, EVENTS, "--json"],
                         capture_output=True, text=True)
    assert res.returncode == 1
    data = json.loads(res.stdout)
    assert data["events"] == 88


def test_cli_exit_zero_when_nothing_matches(tmp_path):
    f = tmp_path / "e.jsonl"
    f.write_text('{"Image": "C:\\\\Windows\\\\notepad.exe"}\n')
    res = subprocess.run([sys.executable, os.path.join(HERE, "sigma_tester.py"), RULES, str(f)],
                         capture_output=True, text=True)
    assert res.returncode == 0
    assert "No rule matched" in res.stdout
