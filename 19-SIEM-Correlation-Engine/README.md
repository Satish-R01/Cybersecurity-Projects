# SIEM Correlation Engine

Python script that reads normalized log events and joins them with correlation rules, like a very small SIEM. I made it because one event alone is often boring, but a few events in a row from the same IP or user tell the real story. This is how a SIEM finds things like "brute force, then a successful login".

## What it does
- Reads events as JSON lines (one event per line, with a `time` and an `event` field)
- Reads rules from a JSON file, so I can add a rule without changing the code
- Each rule has steps that must happen in order, for the same key (like `src_ip`, `user` or `host`), inside a time window
- A step can need a minimum count (for example 5 failed logins) and can match other fields (for example `group` is `Administrators`)
- Shows alerts sorted by severity with the rule name, key, first and last time and the MITRE ATT&CK ID
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/19-SIEM-Correlation-Engine

python3 correlate.py samples/events.jsonl
python3 correlate.py samples/events.jsonl -r samples/rules.json --json
```

Options:
- `-r` rules file (default samples/rules.json)
- `--json` print alerts as JSON

Rule format:
```
{
  "name": "Brute force then success",
  "severity": "HIGH",
  "mitre": "T1110 Brute Force",
  "group_by": "src_ip",
  "window_seconds": 600,
  "steps": [
    {"event": "login_failed", "min_count": 5},
    {"event": "login_success"}
  ]
}
```

## Output on the sample events
```
$ python3 correlate.py samples/events.jsonl
[!] 4 correlated alert(s) from 35 events

SEVERITY RULE                         KEY              EVENTS FIRST -> LAST
----------------------------------------------------------------------------------------------------
HIGH     Brute force then success     203.0.113.45     6      2024-05-14T10:02:10Z -> 2024-05-14T10:03:05Z
         5 failed logins followed by a successful login from the same IP (T1110 Brute Force)
HIGH     New user made admin          svc_backup2      2      2024-05-14T12:10:00Z -> 2024-05-14T12:14:30Z
         An account was created and added to an admin group within 30 minutes (T1136 Create Account, T1098 Account Manipulation)
MEDIUM   Download then execute        WS-12            2      2024-05-14T14:20:00Z -> 2024-05-14T14:21:40Z
         An executable was downloaded and then started on the same host (T1105 Ingress Tool Transfer, T1204 User Execution)
MEDIUM   VPN login then data upload   ravi             3      2024-05-14T15:00:00Z -> 2024-05-14T15:25:00Z
         A VPN login followed by two large uploads to a cloud storage site (T1078 Valid Accounts, T1567 Exfiltration Over Web Service)
```

The sample file is made up, 35 events. It has 4 attacks and some normal activity that should not alert:
- 203.0.113.45 fails 7 times and then logs in as admin
- a new user svc_backup2 is created and added to Administrators 4 minutes later
- WS-12 downloads an exe and PowerShell starts it
- ravi logs in on VPN and uploads about 800 MB to mega.nz
- normal things that should stay quiet: 6 failed logins spread over 6 hours, a new user added to the normal Users group, a pdf opened from explorer, and one upload after a VPN login

## What I'd do as L1 after an alert
- Open the raw events behind the alert and check the time, source and user
- For brute force then success, check if the IP is on a threat feed and reset the password of that account
- For a new admin, ask the person who created the account if it was planned. If not, escalate to L2
- For download then execute, get the hash of the file and check it on VirusTotal, then isolate the host
- For VPN then upload, check what data was uploaded and tell L2 because it can be a data leak

MITRE ATT&CK: T1110 Brute Force, T1136 Create Account, T1098 Account Manipulation, T1105 Ingress Tool Transfer, T1204 User Execution, T1078 Valid Accounts, T1567 Exfiltration Over Web Service.

To prevent it: use MFA, lock accounts after failed logins, limit who can add admins, and block uploads to file sharing sites.

## Limitations
- Events must already be normalized to the field names used in the rules
- Rules only do ordered steps with a count, no "NOT" conditions or counting different values
- Only one alert per key and window, it starts again after an alert
- Time must be in the format 2024-05-14T10:02:10Z

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
