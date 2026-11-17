# Web Attack Log Detector

Python script that reads an Apache or Nginx access log and flags SQL injection, XSS, path traversal, command injection, scanners and directory brute-forcing. I made it to practice what a SOC analyst does when a web server alert comes in.

## What it does
- Parses the combined log format (IP, time, request, status, referer, user agent)
- URL-decodes each request twice, so encoded and double encoded payloads are also caught
- Looks for SQLi, XSS, path traversal and command injection patterns with regex
- Flags known scanner user agents (sqlmap, nikto, nmap, gobuster and others)
- Flags an IP with many 404s as forced browsing
- Prints a summary per IP and the details of every hit
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/05-Web-Attack-Log-Detector

python3 detector.py samples/access.log
python3 detector.py /var/log/nginx/access.log --scan-404 20
python3 detector.py samples/access.log --json
```

## Output on the sample log
```
$ python3 detector.py samples/access.log
[!] 15 suspicious request(s) from 4 IP(s)

Per IP summary:
  203.0.113.50     HIGH    requests=6   SQLi, Scanner
  192.0.2.99       HIGH    requests=4   Command injection, Path traversal
  198.51.100.200   MEDIUM  requests=14  Forced browsing, Scanner
  203.0.113.77     MEDIUM  requests=2   XSS

Details:
  line 8   203.0.113.50     SQLi               500 /products?id=12'
  line 9   203.0.113.50     SQLi               200 /products?id=12%27%20OR%20%271%27%3D%271
  line 10  203.0.113.50     SQLi               200 /products?id=12%20UNION%20SELECT%20username,password%20FROM%20users--
  line 11  203.0.113.50     SQLi               200 /products?id=12;SELECT%20SLEEP(5)--
  line 12  203.0.113.77     XSS                200 /search?q=%3Cscript%3Ealert(1)%3C/script%3E
  line 13  203.0.113.77     XSS                200 /search?q=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
  line 14  192.0.2.99       Path traversal     200 /download?file=../../../../etc/passwd
  line 15  192.0.2.99       Path traversal     403 /download?file=%2e%2e%2f%2e%2e%2fetc%2fshadow
  line 16  192.0.2.99       Path traversal     404 /download?file=..%252f..%252fetc/passwd
  line 17  192.0.2.99       Path traversal     200 /ping?host=8.8.8.8;cat%20/etc/passwd
  line 17  192.0.2.99       Command injection  200 /ping?host=8.8.8.8;cat%20/etc/passwd
  line 18  198.51.100.200   Scanner            200 /
  line 19  198.51.100.200   Scanner            404 /admin
  line 32  203.0.113.50     Scanner            200 /products?id=1
        198.51.100.200   Forced browsing    13 not-found requests
```

The sample log is 33 fake lines: some normal traffic and a few attackers from documentation IP ranges (203.0.113.x, 192.0.2.x, 198.51.100.x).

## What I'd do as L1 after an alert
- Look at the status code. 200 or 500 on an attack request means the app answered, so it is more serious than 403 or 404
- SQLi with 200 and a big response size (like the UNION SELECT above) can mean data was leaked, escalate to L2
- Search the log for the same IP and see what else it requested, also check other servers
- For scanners and forced browsing, block the IP on the firewall or WAF if it is not a known pentest
- Check the IP on AbuseIPDB or VirusTotal before blocking

MITRE ATT&CK: T1190 Exploit Public-Facing Application, T1595.002 Vulnerability Scanning, T1083 File and Directory Discovery.

## Limitations
- Regex rules, so some false positives and some attacks will be missed
- Only the URL is checked, not POST bodies (they are not in access logs)
- Only the combined log format is supported

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
