import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from checker import analyze, lookalike, check_url

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def run(name):
    return analyze(os.path.join(SAMPLES, name))


def test_legit_email_is_low_risk():
    r = run("legit_newsletter.eml")
    assert r["verdict"] == "LOW RISK" and r["score"] == 0


def test_paypal_phish_is_phishing():
    r = run("paypal_phish.eml")
    assert r["verdict"] == "PHISHING"
    assert r["auth"]["spf"] == "fail" and r["auth"]["dmarc"] == "fail"
    assert any("Reply-To" in f for f in r["findings"])
    assert any("Invoice_8812.pdf.exe" in f for f in r["findings"])
    assert any("Link text shows" in f for f in r["findings"])


def test_password_expiry_is_suspicious():
    r = run("password_expiry.eml")
    assert r["verdict"] == "SUSPICIOUS"
    assert any("URL shortener" in f for f in r["findings"])


def test_lookalike_domains():
    assert lookalike("paypa1-support.com") == "paypal"
    assert lookalike("rnicrosoft.com") == "microsoft"
    assert lookalike("paypal.com") is None
    assert lookalike("github.com") is None


def test_check_url():
    _, issues = check_url("http://45.67.89.10/login")
    assert "uses an IP address" in issues and "not HTTPS" in issues
    assert check_url("https://github.com/")[1] == []
