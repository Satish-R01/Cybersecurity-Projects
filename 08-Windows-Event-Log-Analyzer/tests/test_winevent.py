import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import winevent

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "samples", "events.jsonl")


def ev(i, **d):
    return {"EventID": i, "TimeCreated": "2026-11-18T10:00:00", "Data": d}


def rules(alerts):
    return [a["rule"] for a in alerts]


def test_log_cleared():
    assert "Audit log cleared" in rules(winevent.analyze([ev(1102, SubjectUserName="x")]))


def test_admin_group_add():
    a = winevent.analyze([ev(4732, MemberName="bob", GroupName="Administrators")])
    assert a[0]["rule"] == "Added to privileged group"


def test_normal_group_ignored():
    assert winevent.analyze([ev(4732, MemberName="bob", GroupName="Printers")]) == []


def test_encoded_powershell():
    a = winevent.analyze([ev(4688, CommandLine="powershell -enc AAAA")])
    assert "encoded PowerShell" in a[0]["rule"]


def test_failed_logons_below_limit():
    events = [ev(4625, TargetUserName="a", IpAddress="1.2.3.4")] * 3
    assert winevent.analyze(events) == []


def test_success_after_failures():
    events = [ev(4625, TargetUserName="a", IpAddress="1.2.3.4")] * 5
    ok = ev(4624, TargetUserName="a", IpAddress="1.2.3.4", LogonType="10")
    ok["TimeCreated"] = "2026-11-18T11:00:00"
    r = rules(winevent.analyze(events + [ok]))
    assert "Many failed logons" in r and "Successful logon after failures" in r


def test_sample_file():
    r = rules(winevent.analyze(winevent.load_events(SAMPLE)))
    for x in ["Audit log cleared", "Successful logon after failures",
              "User account created", "Suspicious new service"]:
        assert x in r
    assert len(r) == 8


def test_cli_exit_code():
    p = subprocess.run([sys.executable, os.path.join(os.path.dirname(SAMPLE), "..", "winevent.py"),
                        SAMPLE, "--json"], capture_output=True, text=True)
    assert p.returncode == 1
    assert p.stdout.startswith("[")
