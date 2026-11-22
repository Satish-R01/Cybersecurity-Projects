# Reflected XSS Tester

Python script that tests URL parameters for reflected XSS. It sends payloads with a random marker and checks how the value comes back in the HTML. I made it while learning web application penetration testing, because XSS is one of the most common bugs in bug bounty and I wanted to understand what makes a reflection exploitable and what does not.

It does not run JavaScript. It only reads the response and checks if the dangerous characters came back unencoded. A small vulnerable lab app is included so you can practice on your own machine.

OWASP: this covers A03:2021 Injection (cross-site scripting) and OWASP WSTG-INPV-01 (Testing for Reflected Cross Site Scripting).

## What it does
- Takes a URL, finds its parameters (or uses `-p`) and puts a payload with a unique marker in each one
- Payloads: script tag, img onerror, svg onload, attribute break, event handler, mixed case script and nested script (for weak filters)
- Tells if the value was not reflected, encoded, or UNENCODED
- Guesses the context where it landed: html, attribute or script
- Can read many URLs from a file
- Refuses to test anything that is not localhost unless you pass `--i-have-permission`
- Exit code is 1 when a finding is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/13-Reflected-XSS-Tester

python3 lab_app.py 8000 &
python3 xss_tester.py "http://127.0.0.1:8000/search?q=test"
python3 xss_tester.py "http://127.0.0.1:8000/attr?v=hello" -p v
python3 xss_tester.py -f samples/targets.txt
```

The lab app has four pages. `/search` prints input as it is. `/greet` removes the word script once, so it is a weak filter. `/attr` puts input inside a quoted attribute. `/safe` encodes the output.

## Example
```
$ python3 xss_tester.py "http://127.0.0.1:8000/greet?name=satish"
[!] http://127.0.0.1:8000/greet?name=satish param=name payload=img onerror context=html
[!] http://127.0.0.1:8000/greet?name=satish param=name payload=svg onload context=html
[!] http://127.0.0.1:8000/greet?name=satish param=name payload=attribute break context=html
[!] http://127.0.0.1:8000/greet?name=satish param=name payload=event handler context=html
[!] http://127.0.0.1:8000/greet?name=satish param=name payload=mixed case script context=html
[!] http://127.0.0.1:8000/greet?name=satish param=name payload=nested script context=script

6 reflected XSS finding(s)
```

The normal script tag was removed by the filter, but the nested one `<scrscriptipt>` turns into `<script>` after the filter removes the middle word. Other tags and the mixed case script were not filtered at all. This is why removing bad words is not a fix. Output encoding is.

## Please read
Use this only on targets you own or have written permission to test. The lab app listens on 127.0.0.1 only. Do not expose it to a network.

## What I'd check in a pentest
- Test every parameter, also the ones that look harmless like page, lang and sort
- Look at the context first. In an attribute I need a quote, in a script block I need to break the string
- Check the Content-Type, a reflection in JSON is not the same as one in HTML
- Check if CSP is set, it can stop the payload even when the reflection is real
- The fix is output encoding for the right context, plus a good CSP

## Limitations
- It does not run a browser, so it cannot confirm the script really executes
- It only does GET parameters, no forms, headers or DOM XSS
- The context guess is simple and can be wrong on messy HTML
- Payload list is short and can be extended in `PAYLOADS`

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
