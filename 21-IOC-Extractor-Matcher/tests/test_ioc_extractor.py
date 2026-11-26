import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ioc_extractor as ioc

ROOT = os.path.join(os.path.dirname(__file__), "..")
REPORT = os.path.join(ROOT, "samples", "report.txt")
BLOCK = os.path.join(ROOT, "samples", "blocklist.txt")


def test_refang():
    assert ioc.refang("hxxp://evil[.]com") == "http://evil.com"
    assert ioc.refang("10[.]1[.]2[.]3") == "10.1.2.3"
    assert ioc.refang("a[@]b(.)com") == "a@b.com"


def test_private_ip_skipped():
    r = ioc.extract("hosts 10.0.0.5 192.168.1.1 127.0.0.1 and 8.8.8.8")
    assert r["ip"] == ["8.8.8.8"]


def test_invalid_ip_skipped():
    assert ioc.extract("value 999.1.2.3")["ip"] == []


def test_hash_types_not_mixed():
    sha = "a" * 64
    r = ioc.extract("h " + sha)
    assert r["sha256"] == [sha]
    assert r["md5"] == [] and r["sha1"] == []


def test_file_names_not_domains():
    r = ioc.extract("opened invoice.docx and run.exe from evil.com")
    assert r["domain"] == ["evil.com"]


def test_email_domain_kept():
    r = ioc.extract("mail bob@bad.org now")
    assert r["email"] == ["bob@bad.org"]
    assert "bad.org" in r["domain"]


def test_cve_upper():
    assert ioc.extract("saw cve-2021-44228")["cve"] == ["CVE-2021-44228"]


def test_subdomain_match():
    hits = ioc.match({"domain": ["c2.evil.com"]}, {"evil.com": "c2"})
    assert hits and hits[0]["tag"] == "c2"


def test_url_host_match():
    hits = ioc.match({"url": ["http://1.2.3.4:80/x"]}, {"1.2.3.4": "bad"})
    assert len(hits) == 1


def test_sample_report():
    with open(REPORT) as f:
        r = ioc.extract(f.read())
    assert "45.61.137.22" in r["ip"] and "185.220.77.14" in r["ip"]
    assert "10.20.30.40" not in r["ip"]
    assert "c2.update-check.xyz" in r["domain"]
    assert "CVE-2017-11882" in r["cve"]
    assert len(r["sha256"]) == 1 and len(r["sha1"]) == 1 and len(r["md5"]) == 1
    hits = ioc.match(r, ioc.load_blocklist(BLOCK))
    values = {h["value"] for h in hits}
    assert "185.220.77.14" in values and "c2.update-check.xyz" in values


def test_cli_exit_code_and_json():
    p = subprocess.run([sys.executable, os.path.join(ROOT, "ioc_extractor.py"), REPORT,
                        "-b", BLOCK, "--json"], capture_output=True, text=True)
    assert p.returncode == 1
    assert json.loads(p.stdout)["matches"]
