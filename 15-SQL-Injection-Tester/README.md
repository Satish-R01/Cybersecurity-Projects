# SQL Injection Tester

Python script that tests a URL parameter for SQL injection. It sends error payloads and true/false payload pairs and checks how the page changes. I made it while learning web application penetration testing, because SQL injection is still one of the most serious bugs and I wanted to understand how a tester sees it from outside.

A small vulnerable lab app with an in-memory SQLite database is included, so you can practice on your own machine.

OWASP: this covers A03:2021 Injection and OWASP WSTG-INPV-05 (Testing for SQL Injection).

## What it does
- Takes a URL with parameters and tests each one (or one with `-p`)
- Error-based check: adds a quote to the value and looks for database error text (SQLite, MySQL, PostgreSQL, MSSQL, Oracle)
- Boolean-based check: sends a true condition (`AND 1=1`) and a false one (`AND 1=2`). If the true page matches the normal page and the false page is different, the parameter is probably injectable
- Works on pages that hide errors, because it compares page content
- Refuses to test anything that is not localhost unless you pass `--i-have-permission`
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/15-SQL-Injection-Tester

python3 lab_app.py 8000 &
python3 sqli_tester.py "http://127.0.0.1:8000/product?id=1"
python3 sqli_tester.py "http://127.0.0.1:8000/search?q=mouse" -p q
python3 sqli_tester.py "http://127.0.0.1:8000/safe?id=1"
```

The lab app has three pages. `/product` puts the id in the query and shows database errors. `/search` is also vulnerable but shows no errors. `/safe` uses a parameterized query.

## Example
```
$ python3 sqli_tester.py "http://127.0.0.1:8000/product?id=1"
[!] param=id error-based payload=' (SQLite error, status 500)
[!] param=id boolean-based payload=numeric AND (true=13 bytes, false=10 bytes)

2 SQL injection finding(s)
```

On `/search` there is no error text at all, but the boolean check still finds it because the false condition returns "no results". On `/safe` nothing is found.

## Please read
Use this only on targets you own or have written permission to test. The lab app listens on 127.0.0.1 only. Do not expose it to a network. The tester sends only harmless test payloads, no data is dumped.

## What I'd check in a pentest
- Test every parameter, also cookies and headers, not only the visible ones
- A 500 error after a single quote is a good first sign
- If there is no error, compare the true and false pages
- Confirm manually in Burp before reporting
- The fix is parameterized queries, not filtering quotes

## Limitations
- GET parameters only, no POST body, cookies or headers
- No time-based check, so blind injection with identical pages is missed
- Dynamic pages (ads, timestamps) can give false positives on the boolean check
- It does not exploit anything or extract data

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
