# HTTP Security Headers Checker

Python script that reads saved HTTP responses and checks the security headers: CSP, HSTS, X-Frame-Options, cookie flags, CORS and a few more. I made it while learning web application penetration testing, because missing headers show up in almost every web app report and I wanted to understand each one properly.

It reads response headers from a file. It can also fetch headers from one URL with `--url`, but only use that on a site you own or have permission to test.

OWASP: this covers A05:2021 Security Misconfiguration, and the tests in OWASP WSTG-CONF-07 (HTTP Strict Transport Security), WSTG-CLNT-09 (Clickjacking), WSTG-CLNT-07 (CORS) and WSTG-SESS-02 (Cookie Attributes).

## What it does
- Parses raw HTTP responses (status line and headers), many in one file separated by `###`
- Checks Strict-Transport-Security: missing, short max-age, no includeSubDomains
- Checks Content-Security-Policy: missing, `unsafe-inline`, `unsafe-eval`, wildcard, no default-src
- Checks clickjacking protection (X-Frame-Options or CSP frame-ancestors)
- Checks X-Content-Type-Options, Referrer-Policy and Permissions-Policy
- Flags version leaks in Server and X-Powered-By
- Flags risky CORS (`*` with credentials, `null` origin)
- Checks Set-Cookie for Secure, HttpOnly and SameSite
- Gives a score out of 100 and a grade A to F
- Exit code is 1 when something HIGH or MEDIUM is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/09-HTTP-Security-Headers-Checker

python3 headers_checker.py samples/responses.txt
python3 headers_checker.py samples/responses.txt --json
python3 headers_checker.py --url https://your-own-site.example
```

`samples/responses.txt` has three made-up responses: a badly configured shop, a login page with weak settings and a well configured site.

## Example
```
$ python3 headers_checker.py samples/responses.txt
https://shop.example.test/  (HTTP 200)  score 0  grade F
  HIGH    hsts_missing           No Strict-Transport-Security. Browsers can be downgraded to HTTP (sslstrip).
  HIGH    csp_missing            No Content-Security-Policy. XSS has nothing to limit it.
  HIGH    cors_wildcard_creds    CORS allows * with credentials.
  MEDIUM  cookie_no_httponly     Cookie 'PHPSESSID' has no HttpOnly flag.
  ...

https://secure.example.test/  (HTTP 200)  score 100  grade A
  nothing found
```

## Please read
Use this only on sites you own or have written permission to test. The sample responses here are made up for practice.

## What I'd check in a pentest
- A missing CSP on a page that reflects input makes an XSS bug much easier to use
- A session cookie without HttpOnly can be stolen with XSS
- CORS with `*` and credentials, or an origin that is just reflected back, can leak user data to another site
- Missing frame protection on a page with a sensitive button (transfer, delete) is a clickjacking report
- Version numbers in Server and X-Powered-By tell me what to search exploits for

## Limitations
- It only reads headers, it does not check if a CSP actually blocks a real payload
- Missing headers alone are usually low impact, so I check how they combine with other bugs
- It does not follow redirects and fetches only one URL at a time
- The CSP checks are simple string checks, not a full CSP parser

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
