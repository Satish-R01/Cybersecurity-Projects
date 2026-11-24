# Cybersecurity Projects

Small security tools I'm building while learning SOC, networking, Linux and VAPT. Each folder has its own README, sample data and tests.

| No. | Project | Description |
|---|---|---|
| 01 | [SSH Brute-Force Detector](./01-SSH-Brute-Force-Detector) | Finds brute-force and password spraying in Linux auth.log |
| 02 | [Phishing Email Checker](./02-Phishing-Email-Checker) | Checks .eml files for phishing signs (SPF/DKIM/DMARC, lookalike domains, bad links, attachments) and gives a risk score |
| 03 | [Nmap Automation and Report](./03-Nmap-Automation-Report) | Runs an nmap scan (or reads saved XML) and makes CSV and HTML reports with risky ports highlighted |
| 04 | [File Integrity Monitor](./04-File-Integrity-Monitor) | Makes a SHA-256 baseline of a folder and reports modified, new, deleted files and permission changes |
| 05 | [Web Attack Log Detector](./05-Web-Attack-Log-Detector) | Reads Apache/Nginx access logs and finds SQL injection, XSS, path traversal, scanners and directory brute-forcing |
| 06 | [DNS Tunneling Detector](./06-DNS-Tunneling-Detector) | Reads Zeek dns.log and finds DNS tunneling and data exfiltration using length, entropy, TXT/NULL queries and hex decoding |
| 07 | [JWT Security Tester](./07-JWT-Security-Tester) | Checks a JSON Web Token for alg none, weak HMAC secrets, missing or long expiry and sensitive claims, and can forge an alg:none token to test the server |
| 08 | [Windows Event Log Analyzer](./08-Windows-Event-Log-Analyzer) | Reads Windows event logs (JSON lines) and finds brute force, new admin users, encoded PowerShell, bad services and cleared logs |
| 09 | [HTTP Security Headers Checker](./09-HTTP-Security-Headers-Checker) | Reads saved HTTP responses and checks CSP, HSTS, clickjacking headers, CORS, cookie flags and version leaks, then gives a score and grade |
| 10 | [Suricata Alert Summarizer](./10-Suricata-Alert-Summarizer) | Reads Suricata eve.json and summarizes alerts by signature, maps them to MITRE ATT&CK and lists high severity alerts that were not blocked |
| 11 | [Open Redirect Tester](./11-Open-Redirect-Tester) | Tests URL parameters with redirect payloads and bypass tricks against a local lab app and reports when the Location header leaves the host |
| 12 | [Honeypot Log Parser](./12-Honeypot-Log-Parser) | Reads Cowrie SSH honeypot logs and finds brute force, scanners and attackers who logged in, then flags downloads, SSH keys, miners and maps them to MITRE ATT&CK |
| 13 | [Reflected XSS Tester](./13-Reflected-XSS-Tester) | Sends XSS payloads to URL parameters of a local lab app and checks if the value comes back unencoded, and in which context |
| 14 | [Firewall Log Analyzer](./14-Firewall-Log-Analyzer) | Reads iptables/UFW logs and finds port scans, host sweeps, repeated hits on sensitive ports and blocked outbound beaconing, with MITRE ATT&CK IDs |
| 15 | [SQL Injection Tester](./15-SQL-Injection-Tester) | Tests URL parameters for error-based and boolean-based SQL injection against a local lab app and shows the evidence |
| 16 | [Linux Auditd Analyzer](./16-Linux-Auditd-Analyzer) | Reads the Linux audit log and finds reverse shells, encoded commands, programs run from /tmp, changes to passwd and shadow, new accounts and audit tampering, with MITRE ATT&CK IDs |

Satish R - https://www.linkedin.com/in/cybersatish
