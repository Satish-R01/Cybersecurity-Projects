# Nmap Automation and Report

Python script that runs an nmap scan (or reads a saved nmap XML file) and turns the result into a CSV and an HTML report. I made it to practice the scan and report work that comes with recon and vulnerability assessment.

## What it does
- Runs `nmap -sV -T4` on a target with subprocess and saves the XML (`-oX`)
- Or skips the scan and reads an XML file you already have (`--xml`)
- Lists only the open ports with service name and version
- Marks risky ports (Telnet, FTP, SMB, RDP, VNC, databases...) with a short reason
- Writes a CSV file and an HTML report where the risky rows are highlighted
- Only uses the Python standard library. nmap has to be installed for live scans

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/03-Nmap-Automation-Report

# use the sample scan, no nmap needed
python3 nmap_report.py --xml samples/scanme.xml

# live scan, only on hosts you are allowed to scan
python3 nmap_report.py --target scanme.nmap.org
python3 nmap_report.py --target 192.168.56.20 --nmap-args "-p 1-1000" --csv lab.csv --html lab.html
```

scanme.nmap.org is the machine the nmap project provides for people to practice on. Do not scan anything else without permission.

## Output on the sample scan
```
Host 45.33.32.156 (scanme.nmap.org)  OS: Linux 3.2 - 4.9
  22/tcp     ssh            OpenSSH 6.6.1p1 Ubuntu
  80/tcp     http           Apache httpd 2.4.7
  9929/tcp   nping-echo     Nping echo
  31337/tcp  tcpwrapped     
Host 192.168.56.20 (lab-win7)  OS: Microsoft Windows 7 SP1
  21/tcp     ftp            vsftpd 2.3.4   <-- FTP sends passwords in clear text
  23/tcp     telnet         Linux telnetd   <-- Telnet sends everything in clear text
  135/tcp    msrpc          Microsoft Windows RPC   <-- Windows RPC exposed
  445/tcp    microsoft-ds      <-- SMB exposed (check patching, EternalBlue style bugs)
  3389/tcp   ms-wbt-server  Microsoft Terminal Service   <-- RDP exposed (brute force target)

2 host(s) up, 9 open port(s), 5 flagged
Wrote /tmp/report.csv and /tmp/report.html
```

The sample file `samples/scanme.xml` is written by me in the same format as `nmap -oX`. The scanme.nmap.org part follows what that host usually shows, but the versions in it are not from a fresh scan, so do not treat them as current. The second host (192.168.56.20) is a made-up lab machine with old and risky services. I did not run a live scan in the environment where I built this, so the live scan path is only tested with a mocked subprocess. Run it once on your own machine to check.

## What I'd do as L1 / junior pentester with a result like this
- Check each flagged port: does this server really need it exposed? Telnet and FTP should be replaced by SSH and SFTP
- Compare with the last scan. A new open port nobody asked for is worth a ticket
- Look up the version (for example vsftpd 2.3.4 or OpenSSH 6.6) on the CVE database to see if it is vulnerable
- For a scan on a production network, tell the owner first and keep the scan time in the ticket

MITRE ATT&CK: T1046 (network service discovery), T1595.001 (active scanning, IP blocks). This is what an attacker does first, so the report also shows what they would see.

## Limitations
It only looks at open TCP ports from the XML. No UDP special handling, no NSE script output, and the risky port list is my own short list.

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
