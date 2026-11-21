# Open Redirect Tester

Python script that tests a URL parameter for open redirect. It sends a list of redirect payloads and checks if the Location header sends the user to a different host. I made it while learning web application penetration testing, because open redirect is an easy bug bounty finding and it is often used to make phishing links look trusted.

It does not follow redirects. It only reads the status code and the Location header. A small vulnerable lab app is included so you can practice on your own machine.

OWASP: this covers A01:2021 Broken Access Control (unvalidated redirects) and OWASP WSTG-CLNT-04 (Testing for Client-side URL Redirect).

## What it does
- Takes a URL with a parameter like `next`, `url` or `redirect` and replaces its value with payloads
- Payloads: absolute URL, `//host`, `/\host`, `///host`, `user@host` trick, trusted-prefix trick, `https:host`, encoded slashes and `javascript:`
- Reports a finding when the Location header points to a host other than the target
- Treats relative paths and same-host URLs as safe
- Can read many URLs from a file
- Refuses to test anything that is not localhost unless you pass `--i-have-permission`
- Exit code is 1 when a redirect is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/11-Open-Redirect-Tester

python3 lab_app.py 8000 &
python3 redirect_tester.py "http://127.0.0.1:8000/login?next=/"
python3 redirect_tester.py "http://127.0.0.1:8000/go?url=/home" -p url
python3 redirect_tester.py -f samples/targets.txt --json
```

The lab app has three pages. `/login` redirects anywhere. `/go` only checks that the value starts with `/` or `http://localhost`, so it is weak. `/safe` only allows local paths.

## Example
```
$ python3 redirect_tester.py "http://127.0.0.1:8000/go?url=/home"
[!] param=url payload=protocol relative -> 302 //evil.example/
[!] param=url payload=backslash -> 302 /\evil.example
[!] param=url payload=triple slash -> 302 ///evil.example
[!] param=url payload=encoded slashes -> 302 //evil.example

4 open redirect finding(s)
```

The plain `https://evil.example/` payload was blocked on `/go`, but the check only looks at the start of the string, so other forms got through. This is why a blocklist or a startswith check is not enough.

## Please read
Use this only on targets you own or have written permission to test. The lab app listens on 127.0.0.1 only. Do not expose it to a network. `evil.example` is a reserved example name, nothing is sent to it.

## What I'd check in a pentest
- Look for parameters named next, url, redirect, return, continue, dest
- Test login, logout and SSO callback pages first, they redirect a lot
- Try the bypass forms, not only the full URL
- Check if the redirect can be chained with OAuth to leak a token
- The fix is to allow only relative paths or a fixed list of hosts

## Limitations
- It only checks the Location header. Redirects done by JavaScript or meta refresh are not found
- It sends GET requests only and does not log in
- Payload list is short and can be extended in `PAYLOADS`

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
