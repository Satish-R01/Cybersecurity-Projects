# IDOR Tester

Python script that tests for IDOR (insecure direct object reference). You give it a URL with `{id}` in it and a login token. It walks a range of IDs and reports the ones that return data owned by another user. I made it while learning web application penetration testing, because IDOR is one of the most common bug bounty findings and it is easy to miss when you only click through the app.

It only sends GET requests. A small vulnerable lab app is included so you can practice on your own machine.

OWASP: this covers A01:2021 Broken Access Control and OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References).

## What it does
- Takes a URL template like `http://127.0.0.1:8000/api/orders/{id}` and an ID range like `101-110`
- Sends each request with the bearer token of the user you are testing as
- Reads the owner field in the JSON (owner, user, username, name) and compares it with your user
- Marks a response as IDOR when it returns 200 with someone else's data
- Marks 401/403 as denied and 404 as missing, so those are not findings
- Refuses to test anything that is not localhost unless you pass `--i-have-permission`
- Exit code is 1 when an IDOR is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/17-IDOR-Tester

python3 lab_app.py 8000 &
python3 idor_tester.py "http://127.0.0.1:8000/api/orders/{id}" --ids 101-104 --token alice-token --me alice
python3 idor_tester.py "http://127.0.0.1:8000/api/safe-orders/{id}" --ids 101-104 --token alice-token --me alice
```

The lab app has three endpoints. `/api/orders/<id>` and `/api/profile/<id>` never check the owner, so they are vulnerable. `/api/safe-orders/<id>` checks the owner and returns 404 for other people's orders. `samples/targets.txt` has the same three as ready commands.

## Example
```
$ python3 idor_tester.py "http://127.0.0.1:8000/api/orders/{id}" --ids 101-104 --token alice-token --me alice
[ ] id=101 status=200 own owner=alice
[!] id=102 status=200 idor owner=bob
[!] id=103 status=200 idor owner=carol
[!] id=104 status=200 idor owner=dave

3 IDOR finding(s)
```

Alice is logged in, but she can read orders 102 to 104. The server checks that she is logged in, but not that the order is hers.

## Please read
Use this only on targets you own or have written permission to test. The lab app listens on 127.0.0.1 only. Do not expose it to a network. Even on a permitted target, keep the ID range small, because you are reading real users' data.

## What I'd check in a pentest
- Use two accounts, and try account A's token on account B's IDs
- Look at IDs in the path, the query string, the JSON body and headers
- Check different methods too, a GET can be safe while PUT and DELETE are not
- Do not trust random-looking IDs or UUIDs, they leak in other responses
- The fix is to check the owner on the server for every request

## Limitations
- It only checks GET requests with a token in the Authorization header
- It needs an owner field in the JSON response to compare. Without it, the result is not marked as IDOR
- It cannot find IDOR in POST bodies or in cookies-based sessions yet

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
