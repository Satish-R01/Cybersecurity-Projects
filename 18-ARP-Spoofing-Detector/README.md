# ARP Spoofing Detector

Python script that reads saved ARP traffic or an ARP table and finds ARP spoofing (ARP poisoning). I made it while preparing for CEH, because ARP spoofing is how a man-in-the-middle attack starts on a LAN, and I wanted to see what it looks like in real packets and not only in theory.

It does not send any packets. It only reads files you saved yourself with tcpdump or `arp -a`.

CEH: this covers CEH v12/v13 Module 08 Sniffing (ARP poisoning and how to detect it). MITRE ATT&CK T1557.002 ARP Cache Poisoning.

## What it does
- Reads tcpdump ARP output (`tcpdump -n -e arp`) and also works without `-e`
- Reads an ARP table from `arp -a` on Linux or Windows with `--table`
- Compares IPs with a trusted list (like the real gateway MAC) and alerts when the MAC changes
- Finds one IP that shows up with two or more MACs
- Finds one MAC that answers for many IPs (3+, or 2+ in a table)
- Finds replies that nobody asked for (5+ from one MAC), which is what arpspoof and Ettercap send
- Finds frames where the Ethernet sender is not the MAC inside the ARP reply
- Finds ARP scans, one host asking for many IPs (20+), like netdiscover or `nmap -sn` on a LAN
- Shows a severity and the MITRE ATT&CK ID for each alert
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/18-ARP-Spoofing-Detector

python3 arp_detector.py samples/arp_capture.txt -t samples/trusted.txt
python3 arp_detector.py samples/arp_table.txt --table -t samples/trusted.txt
python3 arp_detector.py samples/arp_table_clean.txt --table -t samples/trusted.txt
```

To check your own lab network:
```
sudo tcpdump -n -e -l arp > my_arp.txt     # stop it with Ctrl+C after some time
arp -a > my_table.txt
python3 arp_detector.py my_arp.txt -t samples/trusted.txt
python3 arp_detector.py my_table.txt --table -t samples/trusted.txt
```

Put your real gateway IP and MAC in the trusted file first. You can get the MAC from the router label or its admin page.

Options:
- `--table` the file is `arp -a` output
- `-t` file with known good `ip mac` pairs
- `-m` IPs for one MAC before an alert (default 3, or 2 with --table)
- `-u` unsolicited replies before an alert (default 5)
- `-s` different IPs asked before an ARP scan alert (default 20)
- `--json` print alerts as JSON

## Output on the sample capture
```
$ python3 arp_detector.py samples/arp_capture.txt -t samples/trusted.txt
[*] 88 ARP packets read
[!] 6 alert(s) found

SEVERITY  TYPE                    IP               MAC                 MITRE      DETAIL
--------------------------------------------------------------------------------------------------------------
HIGH      MAC mismatch            192.168.1.40     00:0c:29:7f:c1:66   T1557.002  frame from 00:0c:29:7f:c1:66 but ARP says b8:27:eb:6c:20:40 (line 86)
HIGH      One MAC for many IPs    192.168.1.66     00:0c:29:7f:c1:66   T1557.002  3 IPs point to this MAC: 192.168.1.66, 192.168.1.1, 192.168.1.23
HIGH      Trusted IP MAC changed  192.168.1.1      00:0c:29:7f:c1:66   T1557.002  expected 3c:52:82:4a:10:01, seen 00:0c:29:7f:c1:66
MEDIUM    IP-MAC conflict         192.168.1.23     00:0c:29:7f:c1:66   T1557.002  2 MACs for one IP: 08:00:27:3b:91:23, 00:0c:29:7f:c1:66
MEDIUM    Unsolicited replies     -                00:0c:29:7f:c1:66   T1557.002  16 replies nobody asked for
LOW       ARP scan                192.168.1.80     52:54:00:12:aa:80   T1018      asked for 31 different IPs
```

## Output on the sample ARP table
```
$ python3 arp_detector.py samples/arp_table.txt --table -t samples/trusted.txt
[*] 4 ARP table entries read
[!] 2 alert(s) found

SEVERITY  TYPE                    IP               MAC                 MITRE      DETAIL
--------------------------------------------------------------------------------------------------------------
HIGH      One MAC for many IPs    192.168.1.1      00:0c:29:7f:c1:66   T1557.002  2 IPs point to this MAC: 192.168.1.1, 192.168.1.66
HIGH      Trusted IP MAC changed  192.168.1.1      00:0c:29:7f:c1:66   T1557.002  expected 3c:52:82:4a:10:01, seen 00:0c:29:7f:c1:66
```

The gateway 192.168.1.1 and the host 192.168.1.66 have the same MAC in the table. That means my machine is sending traffic for the gateway to 192.168.1.66.

The sample files are made up. The network is 192.168.1.0/24 and the gateway is 192.168.1.1. The capture has:
- normal requests and replies between the gateway, a laptop, a PC and a printer, which should not alert
- one gratuitous ARP from the printer after a reboot, which is under the limit
- 192.168.1.80 asking for 31 IPs one by one (an ARP scan)
- 192.168.1.66 sending 16 replies nobody asked for, telling 192.168.1.23 that it is the gateway and telling the gateway that it is 192.168.1.23 (like arpspoof)
- one crafted reply from 192.168.1.66 that carries the printer's MAC inside

`arp_table_clean.txt` is a normal Windows `arp -a` output with no alerts.

## What I'd do as L1 after an alert
- Note the attacker MAC and find the switch port it is on (`show mac address-table` on the switch)
- Find who owns that MAC from DHCP logs or the asset list
- Check the real gateway MAC on the router and compare
- If it is not a known device, escalate to L2 and ask the network team to shut that switch port
- Look for what was sent through the attacker in that time, like logins over HTTP

To prevent it: Dynamic ARP Inspection (DAI) with DHCP snooping on the switch, port security, static ARP entries for the gateway on important servers, and HTTPS/SSH everywhere so sniffed traffic is encrypted.

## Please read
Use this only on networks you own or have written permission to test. Capturing traffic on a network that is not yours can be illegal. The sample files are made up for practice.

## Limitations
- It reads saved text output, not .pcap files
- A router or load balancer with many IPs on one MAC will show as "One MAC for many IPs", so add it to the trusted list or raise `-m`
- A device that changed its network card or got a new DHCP lease will show as an IP-MAC conflict
- Without `tcpdump -e` the MAC mismatch check cannot work, because the Ethernet sender is not shown

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
