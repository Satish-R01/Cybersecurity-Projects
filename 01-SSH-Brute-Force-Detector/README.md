# 🔐 SSH Brute-Force Detector

A lightweight Python tool that reads Linux SSH authentication logs (`/var/log/auth.log`) and detects brute-force and password-spraying attacks — the same triage a **SOC L1 analyst** does on failed-login alerts.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110-red) ![License](https://img.shields.io/badge/License-MIT-green)

## Features
- Parses `Failed password` / `Invalid user` / `Accepted` SSH events
- Sliding time-window detection (default: 5+ failures in 10 minutes)
- Flags **successful login after failures** → possible account compromise (CRITICAL)
- Distinguishes **Password Guessing (T1110.001)** vs **Password Spraying (T1110.003)**
- Severity scoring: CRITICAL / HIGH / MEDIUM / LOW
- Export alerts to **JSON** or **CSV** (ready for a SIEM or Excel)
- Zero dependencies — Python standard library only
- Exit code `1` when alerts are found (easy to use in cron / scripts)

## Usage
```bash
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/01-SSH-Brute-Force-Detector

# Run on the included sample log
python3 detector.py sample_logs/auth.log -y 2026

# Run on a real server log
sudo python3 detector.py /var/log/auth.log

# Custom threshold/window + reports
python3 detector.py sample_logs/auth.log -y 2026 -t 8 -w 5 --json alerts.json --csv alerts.csv
```

| Option | Meaning | Default |
|---|---|---|
| `-t, --threshold` | Failed attempts that trigger an alert | 5 |
| `-w, --window` | Time window in minutes | 10 |
| `-y, --year` | Year of the log (syslog lines have no year) | current |
| `--json / --csv` | Save alerts to a file | – |

## Sample output
```
[!] 3 suspicious IP(s) found

SEVERITY  IP               FAILS  PEAK  TECHNIQUE
----------------------------------------------------------------------
CRITICAL  185.220.101.3        8     8  T1110.001 Password Guessing
          users: deploy
          !!! SUCCESSFUL LOGIN AFTER FAILURES: deploy @ 2026-11-13 10:30:50
HIGH      45.83.12.7          25    25  T1110.001 Password Guessing
          users: root
MEDIUM    103.21.44.9         12    12  T1110.003 Password Spraying
          users: admin, guest, oracle, postgres, test, ubuntu
```

## How it works
1. Regex-parses each sshd line into (timestamp, user, source IP).
2. Groups failures by IP and finds the peak count inside any sliding window.
3. IPs above the threshold become alerts; one or two usernames = guessing, many = spraying.
4. If the same IP later logs in successfully, the alert is escalated to **CRITICAL**.

## Response playbook (SOC L1)
| Severity | Action |
|---|---|
| CRITICAL | Isolate host, disable/reset the account, check `last`/`history`, escalate to L2 |
| HIGH | Block IP (`ufw deny from <ip>` / firewall), check threat intel (AbuseIPDB) |
| MEDIUM | Block or monitor, verify targeted accounts exist |
| LOW | Monitor |

**Hardening:** key-based SSH auth, disable root login, `fail2ban`, MFA, non-default port.

## Tests
```bash
pip install pytest
python3 -m pytest -q tests
```

## Author
**Satish R** — Cybersecurity trainee (SOC | Network | Linux | VAPT)
[LinkedIn](https://www.linkedin.com/in/cybersatish)

## License
MIT
