# Beaconing Detector

Python script that reads a proxy log and finds hosts that connect to one domain again and again at a fixed interval. This is called beaconing, and it is how malware checks in with its C2 server. I made it because the traffic looks normal one by one, but the timing gives it away, and I wanted to learn how a SOC analyst can hunt for that.

## What it does
- Reads a proxy log in CSV format (time, src_ip, dst_host, dst_port, bytes_out, user_agent)
- Groups connections by source IP, destination and port
- Works out the gap between each connection and checks how regular the gaps are (jitter)
- Gives points for:
  - a very regular interval (low jitter)
  - the same request size every time
  - running for an hour or more
  - only one user agent
- Marks each pair HIGH or MEDIUM
- Allowlist file for domains you trust (time servers, update services)
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/23-Beaconing-Detector

python3 beacon.py samples/proxy.csv
python3 beacon.py samples/proxy.csv -a samples/allowlist.txt -m 5
python3 beacon.py /var/log/proxy.csv --json
```

Options:
- `-m` number of connections before a pair is checked (default 10)
- `-j` max jitter as a fraction of the interval (default 0.2)
- `-a` allowlist file, one domain per line
- `--json` print alerts as JSON

## Output on the sample log
```
$ python3 beacon.py samples/proxy.csv -a samples/allowlist.txt
[!] 2 possible beacon(s) found

SEVERITY  SOURCE        DESTINATION              PORT  CONNS  REASONS
----------------------------------------------------------------------------------------------------
HIGH      10.10.2.41    update-check.cloudsvc-api.net 443   360    regular interval (every ~60s, jitter 3%); same size every time; running for 6.0 hours; one user agent only
HIGH      10.10.2.77    cdn.static-assets-hub.com 8443  48     regular interval (every ~298s, jitter 9%); same size every time; running for 3.9 hours; one user agent only
```

The sample log is made up, 849 connections over 6 hours. It has:
- three normal hosts browsing with random gaps
- 10.10.2.41 calling an update-looking domain every 60 seconds with an old MSIE user agent
- 10.10.2.77 calling a domain on port 8443 every 5 minutes with 15% jitter and a python-requests user agent
- 10.10.2.15 checking time.windows.com every 15 minutes. It is regular but safe, so it is in the allowlist (without the allowlist it shows up as an alert)
- 10.10.2.90 with only 6 connections, under the default limit. Run with `-m 5` to see it

Real malware adds jitter on purpose, so I do not look for a perfect interval. Anything up to 20% jitter still counts.

## What I'd do as L1 after an alert
- Look up the destination: domain age, hosting, VirusTotal and threat feeds
- Check if other hosts talk to the same domain
- Look at the user agent and the process on the host that makes the calls (EDR or Sysmon event ID 3)
- Check what the host did before the first connection (a download, a macro, a new service)
- Block the domain and isolate the host if it looks like C2, then escalate to L2

MITRE ATT&CK: T1071.001 Application Layer Protocol: Web Protocols, T1573 Encrypted Channel, T1029 Scheduled Transfer.

To prevent it: send web traffic only through the proxy, block newly registered domains, and use a good threat feed.

## Limitations
- Only checks one source and destination pair, it does not join many IPs of one domain
- Slow beacons (once a day) need a long log to show a pattern
- Beacons with a lot of jitter (more than 50%) can get past
- Legit apps (telemetry, mail clients, time sync) are also regular, so the allowlist needs work

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
