# Login Rate Limit Tester

Python script that checks if a login page has any limit on wrong passwords. It sends a fixed number of wrong logins to one account and watches for a 429, a Retry-After header or a lockout message. I made it while learning web application penetration testing, because a login with no limit can be brute forced and this is a common bug bounty finding.

It only sends wrong passwords from a small list, so it does not try to break into the account. A small lab app is included so you can practice on your own machine.

OWASP: this covers A07:2021 Identification and Authentication Failures and OWASP WSTG-ATHN-03 (Testing for Weak Lock Out Mechanism).

## What it does
- Takes a login URL and a username, and sends JSON POST requests with wrong passwords
- Marks a response as blocked when it is 429, has a Retry-After header, or says locked or too many attempts
- Tells you at which attempt the first block happened
- Says the login is vulnerable if there is no block after all attempts
- Refuses to test anything that is not localhost unless you pass `--i-have-permission`
- Caps attempts at 100, exit code is 1 when no limit is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/22-Login-Rate-Limit-Tester

python3 lab_app.py 8000 &
python3 rate_limit_tester.py http://127.0.0.1:8000/vuln/login --user alice
python3 rate_limit_tester.py http://127.0.0.1:8000/safe/login --user alice
```

The lab app has two endpoints. `/vuln/login` has no limit. `/safe/login` blocks an account for 30 seconds after 5 failed logins. `samples/targets.txt` has the same commands.

## Example
```
$ python3 rate_limit_tester.py http://127.0.0.1:8000/safe/login --user alice --attempts 7
[ ] attempt=1 status=401 allowed
...
[ ] attempt=5 status=401 allowed
[!] attempt=6 status=429 blocked retry-after=30

Blocked at attempt 6. A limit exists.
```

On `/vuln/login` all attempts come back 401 and the tool says brute force is possible.

## Please read
Use this only on targets you own or have written permission to test. The lab app listens on 127.0.0.1 only. Do not expose it to a network. Even on a permitted target, keep the attempts low, because repeated failed logins can lock real users out.

## What I'd check in a pentest
- Test the limit per account and per IP, they are often different
- Try changing the username case or adding spaces to see if the counter resets
- Check if a header like X-Forwarded-For changes the limit
- Look at other endpoints too, like password reset, OTP and API login
- The fix is a lockout or delay after a few failures, plus MFA

## Limitations
- It only sends JSON POST requests, not form data
- It sends one request at a time, so it cannot find limits that only trigger on fast parallel requests
- A block that looks like a normal 401 with a delay is not detected yet

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
