# IOC Extractor and Matcher

Python script that reads a threat report or an incident note, pulls out all the indicators of compromise (IOCs) and checks them against a blocklist. I made it because analysts get reports full of IPs, domains and hashes, and copying them by hand into a SIEM search is slow and I wanted to see how to automate it.

## What it does
- Extracts IPv4 addresses, domains, URLs, email addresses, CVE IDs, and MD5, SHA1 and SHA256 hashes
- Understands defanged text like hxxp://evil[.]com and 10[.]0[.]0[.]1 and turns it back to normal
- Skips private, loopback and invalid IPs (like 999.1.2.3)
- Skips file names that look like domains (like invoice.docx or load.bin)
- Matches the indicators with a blocklist file (`indicator,tag` per line)
- A subdomain of a blocked domain also matches, and a URL matches when its host is blocked
- Exit code is 1 when there is a match, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/21-IOC-Extractor-Matcher

python3 ioc_extractor.py samples/report.txt
python3 ioc_extractor.py samples/report.txt -b samples/blocklist.txt
python3 ioc_extractor.py samples/report.txt -b samples/blocklist.txt --json
```

Options:
- `-b` blocklist file, one `indicator,tag` per line, lines starting with # are ignored
- `--json` print the indicators and matches as JSON

## Output on the sample report
```
$ python3 ioc_extractor.py samples/report.txt -b samples/blocklist.txt
[+] 18 indicators found
...
[!] 8 match(es) with the blocklist
  ip      185.220.77.14  ->  emotet payload server
  ip      45.61.137.22  ->  known spam relay
  domain  c2.update-check.xyz  ->  emotet c2
  domain  cdn.update-check.xyz  ->  emotet c2
  domain  invoice-portal.top  ->  phishing sender domain
  url     http://185.220.77.14:8080/load.bin  ->  emotet payload server
  sha256  9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  ->  emotet loader
  md5     5d41402abc4b2a76b9719d911017c592  ->  malicious docx
```

The sample report is made up. It is an incident note about a phishing email with a macro document. It has:
- defanged IPs, a defanged URL and a defanged sender domain
- three file hashes (MD5, SHA1, SHA256)
- two CVE IDs and two email addresses
- normal things that should not alert, like 10.20.30.40, 8.8.8.8, microsoft.com, a version number 3.2.1 and the bad value 999.1.2.3

Note that 8.8.8.8, github.com and microsoft.com are extracted but they are not in the blocklist, so they do not match.

## What I'd do as L1 after a match
- Search the matched IPs, domains and hashes in the SIEM and EDR to see which hosts touched them
- Check the domain and hash on VirusTotal and the IP on AbuseIPDB
- If a host already connected to the C2 or ran the file, escalate to L2 and isolate the host
- Block the IPs, domains and URLs on the firewall and proxy, and block the hashes in the EDR
- Add new indicators from the report to the blocklist so the next report is checked too

MITRE ATT&CK: T1566.001 Phishing: Spearphishing Attachment, T1071.001 Application Layer Protocol: Web Protocols, T1105 Ingress Tool Transfer.

To prevent it: keep the blocklist fed from a good threat feed, block macros from the internet, and filter email and DNS.

## Limitations
- Only IPv4, no IPv6 yet
- The blocklist is a plain file, it does not call VirusTotal or any other service
- A word like a.b can look like a domain, so some noise is possible
- Weird defang styles that I did not add will be missed

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
