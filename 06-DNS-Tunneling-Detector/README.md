# DNS Tunneling Detector

Python script that reads a Zeek dns.log and finds hosts that may be using DNS tunneling, for C2 or for sending data out. I made it because DNS is allowed almost everywhere, so attackers like to hide traffic in it, and I wanted to see how a SOC analyst can spot that.

## What it does
- Reads Zeek dns.log in the normal TSV format or in JSON format
- Groups queries by client IP and base domain (handles co.uk, co.in and similar)
- Checks each group for:
  - long subdomains (avg 30+ or max 50+ characters)
  - high Shannon entropy in the subdomain (random looking text like base32)
  - almost every query having a new subdomain
  - lots of TXT or NULL queries
  - lots of NXDOMAIN answers
  - hex encoded data in the name, and tries to decode it
- Gives each group a score and marks it HIGH or MEDIUM
- Allowlist file for domains you trust (CDNs, Microsoft, etc.)
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/06-DNS-Tunneling-Detector

python3 dns_tunnel.py samples/dns.log
python3 dns_tunnel.py samples/dns.log -m 5 -a samples/allowlist.txt
python3 dns_tunnel.py /opt/zeek/logs/current/dns.log --json
```

Options:
- `-m` number of queries from one client to one domain before it is checked (default 20)
- `-a` allowlist file, one domain per line
- `--json` print alerts as JSON

## Output on the sample log
```
$ python3 dns_tunnel.py samples/dns.log
[!] 2 possible DNS tunnel(s) found

SEVERITY  CLIENT          DOMAIN                 QUERIES  REASONS
------------------------------------------------------------------------------------------
HIGH      10.10.1.52      cdn-update.info             30  long subdomains (avg 32, max 32); high entropy (4.22); 30 unique subdomains; 30 TXT/NULL queries
HIGH      10.10.1.37      data-sync-cdn.net           25  long subdomains (avg 56, max 57); 25 unique subdomains; 25 NXDOMAIN; hex data in name
                                                decoded: emp_id,name,email,salary\n
```

The sample log is made up, 226 queries in Zeek TSV format. It has:
- three normal hosts browsing Google, GitHub, Microsoft, Ubuntu updates and so on
- 10.10.1.37 sending a fake employee CSV out as hex chunks in A queries
- 10.10.1.52 talking to a C2 server with random base32 names and TXT queries every 30 seconds
- 10.10.1.60, a slow tunnel with only 6 queries. It is under the default limit, run with `-m 5` to see it
- one host hitting a CDN many times with short names, which should not alert

Hex text has lower entropy than base32 (only 16 characters are used), so the exfil host is not flagged for entropy. It is still caught by length, unique names, NXDOMAIN and the hex decode. This is why I used many checks and not only entropy.

## What I'd do as L1 after an alert
- Look up the domain: when was it registered, who hosts it, is it on VirusTotal or any threat feed
- Check if any other host in the network is querying the same domain
- If the decoded text shows company data (like the CSV above), it is a data leak, escalate to L2 right away
- Find the process on the host making the queries (EDR or Sysmon event ID 22)
- Block the domain on the DNS server or firewall, isolate the host if it looks like C2

MITRE ATT&CK: T1071.004 Application Layer Protocol: DNS, T1048 Exfiltration Over Alternative Protocol, T1132 Data Encoding.

To prevent it: allow DNS only to the internal resolvers, block direct port 53 to the internet, and use DNS filtering.

## Limitations
- Thresholds are fixed numbers, a slow and low tunnel with short names can get past
- Base domain logic is simple, it does not use the full public suffix list
- Only hex decoding is tried, not base32 or base64
- Some legit services (antivirus lookups, CDNs) use long random names, add them to the allowlist

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
