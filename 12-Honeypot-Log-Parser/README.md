# Honeypot Log Parser

Python script that reads a Cowrie (SSH honeypot) JSON log and shows what the attackers did. I made it because a honeypot log is full of noise, and I wanted to sort the bots that only guess passwords from the ones that actually got in and ran commands.

## What it does
- Reads the Cowrie JSON log (one event per line) and groups events by session
- Finds IPs with many failed logins (brute force) and IPs that only connect and leave (scanners)
- Finds sessions where the attacker logged in and checks every command they typed
- Flags downloads, chmod, SSH key changes, cron, miners and history clearing
- Shows the file URL and SHA-256 of anything the attacker downloaded
- Lists the top username and password pairs tried
- Maps the behaviour to MITRE ATT&CK
- Exit code is 1 when there is a finding, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/12-Honeypot-Log-Parser

python3 honeypot_parser.py samples/cowrie.json
python3 honeypot_parser.py samples/cowrie.json -m 5
python3 honeypot_parser.py /home/cowrie/var/log/cowrie/cowrie.json --json
```

Options:
- `-m` failed logins (or empty sessions) needed to flag an IP, default 10
- `--json` print the result as JSON

## Output on the sample log
```
$ python3 honeypot_parser.py samples/cowrie.json
[*] 55 sessions from 5 IPs

Top credentials tried:
    admin    qwerty     3
    pi       12345      3
    test     admin      3
    oracle   toor       2
    root     qwerty     2

SEVERITY IP              FINDING
------------------------------------------------------------------------------------------
HIGH     192.0.2.77      compromised_session: logged in as root/root123, 6 commands
                         behaviour: Looks around the system, Downloads a file, Makes a file executable, Touches cron, Adds an SSH key, Hides its tracks
                         download: http://198.51.100.200/bins/x86 sha256=9f86d081884c7d65...
                         MITRE: T1053.003 Cron, T1070 Indicator Removal, T1082 System Information Discovery, T1098.004 SSH Authorized Keys, T1105 Ingress Tool Transfer, T1222 File Permissions Modification
HIGH     203.0.113.88    compromised_session: logged in as admin/admin, 4 commands
                         behaviour: Downloads a file, Miner or piped shell, Looks around the system
                         MITRE: T1082 System Information Discovery, T1105 Ingress Tool Transfer, T1496 Resource Hijacking
MEDIUM   203.0.113.45    brute_force: 40 failed logins in 40 sessions
                         MITRE: T1110 Brute Force
LOW      198.51.100.9    scanner: 12 sessions with no login attempt
                         MITRE: T1046 Network Service Discovery
LOW      192.0.2.31      login_only: logged in as pi/raspberry, 3 commands
                         behaviour: Looks around the system
                         MITRE: T1082 System Information Discovery

[!] 2 attacker(s) got in and ran commands
```

The sample log is made up, 130 events. It has:
- 203.0.113.45 trying 40 passwords and never getting in
- 198.51.100.9 opening 12 connections and doing nothing
- 192.0.2.77 logging in as root, downloading a binary, adding an SSH key and clearing history
- 203.0.113.88 logging in as admin and running a crypto miner script
- 192.0.2.31 logging in as pi and only running ls, whoami and pwd

The brute force IP has the most events but it is the least dangerous one. The two HIGH sessions are only a few commands each, so I rank by what the attacker did, not by how much noise they made.

## What I'd do as L1 after an alert
- Take the download URL and SHA-256 and check them on VirusTotal
- Add the attacker IPs and the malware server IPs (198.51.100.200, 192.0.2.150) to a blocklist
- Check if any real server got a connection from the same IPs
- Note the passwords that worked, because real servers should never use them
- Escalate to L2 if the same IP or file hash shows up on a production host

MITRE ATT&CK: T1110 Brute Force, T1105 Ingress Tool Transfer, T1098.004 SSH Authorized Keys, T1496 Resource Hijacking, T1070 Indicator Removal.

To prevent it: disable password login for SSH, use keys, block root login and use fail2ban.

## Limitations
- It is made for Cowrie JSON only, not for other honeypots
- Command checks are simple regex, so a hidden or encoded command can be missed
- It does not look up IP reputation or the file hash online
- It reads the whole file, so it is not made for very big logs

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
