# SSH Brute-Force Detector

Python script that reads Linux SSH auth logs (/var/log/auth.log) and finds brute-force and password-spraying attempts. I made it to practice the kind of failed-login triage a SOC L1 analyst does.

## What it does
- Parses "Failed password", "Invalid user" and "Accepted" lines from sshd
- Counts failed attempts per IP inside a time window (default 5 fails in 10 min)
- If the same IP later logs in successfully, marks it CRITICAL (possible compromise)
- Few usernames from one IP = password guessing (T1110.001), many usernames = password spraying (T1110.003)
- Can save results to JSON or CSV
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/01-SSH-Brute-Force-Detector

python3 detector.py sample_logs/auth.log -y 2026
sudo python3 detector.py /var/log/auth.log
python3 detector.py sample_logs/auth.log -y 2026 -t 8 -w 5 --json alerts.json --csv alerts.csv
```

Options:
- `-t` number of fails needed for an alert (default 5)
- `-w` time window in minutes (default 10)
- `-y` year of the log, because syslog lines don't have a year
- `--json`, `--csv` save the alerts

## Output on the sample log
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

The sample log is made up. It has one normal user, one IP attacking root, one IP spraying common usernames, one IP that gets in after 8 tries, and one slow IP that stays under the threshold.

## What I'd do as L1 after an alert
- CRITICAL: disable/reset the account, check `last` and bash history on the server, escalate to L2
- HIGH: block the IP (`sudo ufw deny from <ip>`), check it on AbuseIPDB
- MEDIUM/LOW: block or keep watching

To prevent it: SSH keys instead of passwords, no root login, fail2ban.

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
