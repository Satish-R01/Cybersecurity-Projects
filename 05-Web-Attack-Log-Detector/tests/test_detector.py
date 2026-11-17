import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import detector

ROOT = os.path.join(os.path.dirname(__file__), "..")


def line(path, ua="Mozilla/5.0", status="200", ip="203.0.113.5"):
    return f'{ip} - - [15/Nov/2026:09:00:00 +0000] "GET {path} HTTP/1.1" {status} 100 "-" "{ua}"'


def types(path, ua="Mozilla/5.0"):
    e = detector.parse_line(line(path, ua))
    return detector.check_entry(e)


def test_parse_line():
    e = detector.parse_line(line("/index.html"))
    assert e["ip"] == "203.0.113.5"
    assert e["path"] == "/index.html"
    assert e["status"] == "200"


def test_bad_line_returns_none():
    assert detector.parse_line("this is not a log line") is None


def test_normal_requests_clean():
    assert types("/products?id=12") == []
    assert types("/search?q=blue+shoes") == []
    assert types("/user?name=O'Brien") == []


def test_sqli():
    assert "SQLi" in types("/p?id=1%20UNION%20SELECT%20a,b%20FROM%20users--")
    assert "SQLi" in types("/p?id=1%27%20OR%20%271%27%3D%271")
    assert "SQLi" in types("/p?id=1;SELECT%20SLEEP(5)")


def test_xss():
    assert "XSS" in types("/s?q=%3Cscript%3Ealert(1)%3C/script%3E")
    assert "XSS" in types("/s?q=%3Cimg%20src=x%20onerror=alert(1)%3E")


def test_path_traversal_and_double_encoding():
    assert "Path traversal" in types("/d?f=../../etc/passwd")
    assert "Path traversal" in types("/d?f=..%252f..%252fetc/passwd")


def test_command_injection():
    assert "Command injection" in types("/ping?host=1.1.1.1;cat%20/etc/passwd")


def test_scanner_user_agent():
    assert "Scanner" in types("/", "sqlmap/1.7.2#stable")
    assert "Scanner" in types("/", "Nikto/2.1.6")


def test_forced_browsing():
    lines = [line(f"/x{i}", status="404", ip="198.51.100.9") for i in range(12)]
    findings, _, _ = detector.analyze(lines, scan_404=10)
    assert any(f["type"] == "Forced browsing" for f in findings)


def test_cli_on_sample_exit_code():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "detector.py"),
                        os.path.join(ROOT, "samples", "access.log")],
                       capture_output=True, text=True)
    assert r.returncode == 1
    assert "SQLi" in r.stdout and "XSS" in r.stdout and "Path traversal" in r.stdout


def test_cli_clean_log(tmp_path):
    p = tmp_path / "ok.log"
    p.write_text(line("/index.html") + "\n")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "detector.py"), str(p)],
                       capture_output=True, text=True)
    assert r.returncode == 0
