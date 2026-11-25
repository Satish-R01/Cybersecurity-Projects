# CSRF Token Checker

Python script that checks how a page protects its forms against CSRF (cross-site request forgery). It finds the POST forms, looks for a CSRF token, and then tests if the server really checks it. I made it while learning web application penetration testing, because a token in the form means nothing if the server accepts the request without it.

A small vulnerable lab app is included so you can practice on your own machine.

OWASP: this covers A01:2021 Broken Access Control and OWASP WSTG-SESS-05 (Testing for Cross Site Request Forgery).

## What it does
- Reads the page and finds all forms that use POST
- Looks for a token field with a name like csrf, xsrf, token or authenticity
- Reports a form with no token, and checks if the server accepts the POST anyway
- Sends the form again with the token removed, empty and wrong
- Loads the page twice and reports a token that is the same for different sessions
- Reports a short token and cookies without SameSite
- Refuses to test anything that is not localhost unless you pass `--i-have-permission`
- Exit code is 1 when a HIGH finding exists, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/20-CSRF-Token-Checker

python3 lab_app.py 8000 &
python3 csrf_checker.py http://127.0.0.1:8000/vuln/form
python3 csrf_checker.py http://127.0.0.1:8000/weak/form
python3 csrf_checker.py http://127.0.0.1:8000/safe/form
```

The lab app has three forms. `/vuln/form` has no token. `/weak/form` has a token, but it is always 12345. `/safe/form` has a random token for each session. `samples/` also has two small HTML files to see how a form with and without a token looks.

## Example
```
$ python3 csrf_checker.py http://127.0.0.1:8000/vuln/form
[MEDIUM] cookie sid has no SameSite=Lax/Strict
[HIGH] form /vuln/transfer has no CSRF token field
[HIGH] /vuln/transfer accepts the POST with no token

$ python3 csrf_checker.py http://127.0.0.1:8000/weak/form
[MEDIUM] cookie sid has no SameSite=Lax/Strict
[MEDIUM] token in csrf_token is short (5 chars)
[HIGH] token in csrf_token is the same for different sessions
```

On the weak form the server does check the token, but anyone can read it from their own page and use it against another user.

## Please read
Use this only on targets you own or have written permission to test. The lab app listens on 127.0.0.1 only. Do not expose it to a network. The checker sends real POST requests, so on a real target it can change data. Test with a test account.

## What I'd check in a pentest
- Look at every form that changes something, like email, password, transfer and delete
- Try removing the token, and also try changing the request method
- Check if the token is tied to the session of the user
- Look at the SameSite flag of the session cookie
- Check if the server looks at the Origin or Referer header
- The fix is a random token per session, checked on the server for every state changing request

## Limitations
- It only reads HTML forms, so it cannot test JSON APIs or JavaScript sent tokens
- It treats HTTP 200 as accepted, so an app that returns 200 with an error message gives a false positive
- It does not log in, so it can only test pages that work without a session
- It does not check Origin or Referer headers

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
