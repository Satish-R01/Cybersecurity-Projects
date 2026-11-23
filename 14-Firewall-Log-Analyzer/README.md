# Firewall Log Analyzer

Python script that reads iptables or UFW firewall logs and finds port scans, host sweeps, repeated hits on sensitive ports and blocked outbound beaconing. I made it because the firewall log is one of the first things a SOC analyst checks, and I wanted to learn what the bad patterns look like.

## What it does
- Reads kernel log lines from iptables and UFW (SRC, DST, PROTO, DPT, IN and OUT fields)
- Finds port scans: one source trying many ports on one host (15+ ports)
- Finds host sweeps: one source trying the same port on many hosts (10+ hosts)
- Finds repeated blocked hits on SSH, Telnet, RDP, SMB, MSSQL, MySQL and VNC (10+ hits)
- Finds blocked outbound traffic: an internal host trying the same outside IP and port again and again (8+ tries), which can be malware calling home
- Shows a severity and the MITRE ATT&CK ID for each alert
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/14-Firewall-Log-Analyzer

python3 fw_analyzer.py samples/ufw.log
python3 fw_analyzer.py samples/ufw.log -p 30 -s 20
python3 fw_analyzer.py /var/log/ufw.log --json
```

Options:
- `-p` distinct ports before it is called a port scan (default 15)
- `-s` distinct hosts before it is called a sweep (default 10)
- `-n` hits on a sensitive port (default 10)
- `-b` blocked outbound tries (default 8)
- `--json` print alerts as JSON

## Output on the sample log
```
$ python3 fw_analyzer.py samples/ufw.log
[*] 245 firewall events read, 125 blocked
[!] 4 alert(s) found

SEVERITY  TYPE                     SOURCE           TARGET               COUNT  MITRE
--------------------------------------------------------------------------------------
HIGH      Port scan                203.0.113.7      10.0.0.10               40  T1046
HIGH      Blocked outbound beacon  10.0.0.55        185.220.101.9:4444      14  T1071
MEDIUM    Host sweep               198.51.100.23    port 445                30  T1046
MEDIUM    Sensitive port hits      192.0.2.88       RDP (3389)              25  T1110
```

The sample log is made up, 245 lines in UFW format. It has:
- normal allowed traffic to the web server on ports 80 and 443
- a few random blocked hits on ports like 8080 and 21, which should not alert
- 203.0.113.7 scanning 40 ports on the web server
- 198.51.100.23 checking port 445 on 30 internal hosts
- 192.0.2.88 trying RDP 25 times
- internal host 10.0.0.55 trying 185.220.101.9 on port 4444 every 5 minutes and getting blocked
- 198.51.100.77 with only 4 SSH hits, which is under the limit

## What I'd do as L1 after an alert
- Check the source IP on VirusTotal and AbuseIPDB, and see if it is already on a blocklist
- Check if the same source got through anywhere (ALLOW lines in the same log)
- For a blocked outbound beacon, the internal host is the problem. Find the process on it with EDR, and isolate it if it looks like malware
- For a scan from the internet, block the source and write a short ticket. If the scan came from inside, escalate to L2
- Check that the targeted service (RDP, SMB, SSH) is not open to the internet at all

MITRE ATT&CK: T1046 Network Service Discovery, T1110 Brute Force, T1071 Application Layer Protocol.

To prevent it: do not expose RDP, SMB or SSH to the internet, use a VPN, and block outbound traffic by default.

## Limitations
- Thresholds are fixed numbers, a slow scan over many hours can get past
- Only IPv4 lines in iptables or UFW format are read
- It does not look at time windows, so counts are for the whole file
- A vulnerability scanner run by my own team will also show up as a port scan

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
