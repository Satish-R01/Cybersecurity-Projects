# Suricata Alert Summarizer

Python script that reads a Suricata eve.json file and gives a short summary of the alerts. I made it because a busy IDS makes thousands of alerts, and I wanted to see how an analyst can find the ones that matter first.

## What it does
- Reads eve.json (one JSON event per line) and keeps only the alert events
- Skips flow, dns, http and other event types, and bad lines
- Groups alerts by signature and counts them
- Shows the top source IP, the targets and how many were blocked
- Maps the alert category to a MITRE ATT&CK technique
- Marks noisy signatures (10 or more alerts by default)
- Lists high severity signatures that were not fully blocked
- Exit code is 1 when there is something to look at, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/10-Suricata-Alert-Summarizer

python3 suricata_summary.py samples/eve.json
python3 suricata_summary.py samples/eve.json -m 5
python3 suricata_summary.py /var/log/suricata/eve.json --json
```

Options:
- `-m` alerts needed to call a signature noisy (default 10)
- `--json` print the summary as JSON

## Output on the sample log
```
$ python3 suricata_summary.py samples/eve.json
[*] 88 alerts, 6 signatures

SEVERITY COUNT  TOP SOURCE        SIGNATURE                                    MITRE
------------------------------------------------------------------------------------------------------------------------
MEDIUM   40     203.0.113.45      ET SCAN Potential SSH Scan                   T1046 Network Service Discovery
HIGH     26     198.51.100.77     ET WEB_SERVER SQL Injection Attempt          T1190 Exploit Public-Facing Application
LOW      12     10.0.0.31         ET DNS Query to .top domain                  T1568 Dynamic Resolution
HIGH     6      10.0.0.23         ET MALWARE Possible Reverse Shell Beacon     T1071 Application Layer Protocol
HIGH     3      10.0.0.40         ET EXPLOIT SMB Possible EternalBlue Probe    T1210 Exploitation of Remote Services
MEDIUM   1      10.0.0.50         GPL SNMP public access udp                   T1046 Network Service Discovery

[!] 3 high severity signature(s) not fully blocked:
    ET WEB_SERVER SQL Injection Attempt (26 alerts, 1 blocked) -> 10.0.0.10
    ET MALWARE Possible Reverse Shell Beacon (6 alerts, 0 blocked) -> 192.0.2.99
    ET EXPLOIT SMB Possible EternalBlue Probe (3 alerts, 0 blocked) -> 10.0.0.10
```

The sample log is made up, 118 events and 88 of them are alerts. It has:
- 203.0.113.45 scanning SSH on 10.0.0.5, 40 alerts, noisy but low risk
- 198.51.100.77 trying SQL injection on the web server, only 1 of 26 was blocked
- 10.0.0.23 (an internal host) sending beacons to 192.0.2.99 on port 4444
- an SMB probe that looks like EternalBlue against 10.0.0.10
- DNS alerts, one SNMP alert and 30 flow events that are ignored

The reverse shell beacon has only 6 alerts, so it is easy to miss in a sorted list. This is why I print the high severity list separately and do not only sort by count.

## What I'd do as L1 after an alert
- Start with the internal host that is the source of an alert (10.0.0.23 here), it may already be infected
- Check the destination IP and port on VirusTotal or a threat feed
- For the SQL injection, look at the web server access log and see if any request got a 200 response
- For the scan, check if the same IP hit other hosts, and block it if it keeps coming
- Escalate to L2 if the host is talking to the C2 or the exploit worked

MITRE ATT&CK: T1190 Exploit Public-Facing Application, T1071 Application Layer Protocol, T1210 Exploitation of Remote Services, T1046 Network Service Discovery.

To prevent it: patch SMB and web apps, block outbound traffic that is not needed, and tune the noisy rules so real alerts are not missed.

## Limitations
- MITRE mapping is by category only, so it is rough
- It reads the whole file, so it is not made for very big logs
- It does not look at the payload or the flow events around an alert
- Time windows are not supported, it summarizes the whole file

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
