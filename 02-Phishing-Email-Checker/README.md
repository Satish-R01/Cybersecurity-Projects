# Phishing Email Checker

Python script that reads saved emails (.eml files) and checks them for common phishing signs. I made it to practice the email triage a SOC L1 analyst does when a user reports a suspicious mail.

## What it does
- Reads SPF, DKIM and DMARC results from the Authentication-Results header
- Checks if Reply-To or Return-Path goes to a different domain than From
- Finds lookalike domains like paypa1-support.com or rnicrosoft.com
- Flags a display name that uses a brand (PayPal, Microsoft...) but sends from some other domain
- Checks links: IP address instead of domain, URL shorteners, punycode, plain http, and link text that shows one URL but goes to another
- Looks for urgency words ("account suspended", "within 24 hours"...)
- Flags risky attachments like .exe, .js, .iso, .html and double extensions (invoice.pdf.exe)
- Adds it all up into a score out of 100: LOW RISK (below 30), SUSPICIOUS (30-59), PHISHING (60+)
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/02-Phishing-Email-Checker

python3 checker.py samples/*.eml
python3 checker.py suspicious.eml --json result.json
```

To get an .eml file: in Gmail open the mail, three dots, "Download message". In Outlook, save the mail or drag it to a folder.

## Output on the sample emails
```
=== samples/legit_newsletter.eml
Subject : Your monthly GitHub update
From    : news@github.com
Auth    : SPF=pass  DKIM=pass  DMARC=pass
Score   : 0/100  ->  LOW RISK

=== samples/password_expiry.eml
Subject : Action required: your password expires today
From    : it-support@company-helpdesk.net
Auth    : SPF=pass  DKIM=none  DMARC=none
Score   : 50/100  ->  SUSPICIOUS
  - https://bit.ly/3xYzAbc (URL shortener)
  - Display name 'Microsoft 365 Admin' uses microsoft but sends from company-helpdesk.net
  - Urgency words: password expires, action required
  - DMARC none
  - DKIM none

=== samples/paypal_phish.eml
Subject : URGENT: Your account has been suspended
From    : service@paypa1-support.com   Reply-To: help.desk.verify@gmail.com
Auth    : SPF=fail  DKIM=none  DMARC=fail
Score   : 100/100  ->  PHISHING
  - Risky attachment: Invoice_8812.pdf.exe (double extension)
  - Sender domain paypa1-support.com looks like paypal
  - http://45.67.89.10/paypal/login.php (uses an IP address, not HTTPS)
  - Urgency words: urgent, suspended, verify your account, within 24 hours, unusual activity, account will be closed
  - Reply-To (help.desk.verify@gmail.com) differs from From (service@paypa1-support.com)
  - Link text shows https://www.paypal.com/signin but goes to http://45.67.89.10/paypal/login.php
  - DMARC fail
  - SPF fail
  - Display name 'PayPal Security' uses paypal but sends from paypa1-support.com
  - Return-Path (bounce@mailer-xyz.ru) differs from From domain
  - DKIM none
```

The three sample emails are made up. One is a normal GitHub newsletter, one is a fake "Microsoft 365" password expiry mail with a bit.ly link, and one is a fake PayPal mail with a lookalike domain and a fake attachment (it is just a text file renamed, not malware).

## What I'd do as L1 after a PHISHING result
- Don't click the links or open the attachment. Check URLs on VirusTotal / urlscan.io instead
- Search the mail gateway for the same sender or subject to see who else got it, and pull those mails
- Block the sender domain, the URL and the IP on the mail gateway / proxy
- If someone clicked or entered a password: reset the password, end their sessions, check sign-in logs, escalate to L2
- If the attachment was opened: isolate the machine and escalate

MITRE ATT&CK: T1566.001 (spearphishing attachment), T1566.002 (spearphishing link), T1656 (impersonation).

## Limitations
It only reads the headers the receiving mail server added, it does not check DNS itself. Scores are my own rough weights, so treat it as a first look, not a final verdict.

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
