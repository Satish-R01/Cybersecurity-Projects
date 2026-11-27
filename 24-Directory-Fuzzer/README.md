# Directory Fuzzer

Python script that tries paths from a wordlist on a website and lists the ones that exist. It finds things like /.env, /.git/HEAD, backup.zip and admin panels that nobody linked to. I made it while learning web application penetration testing, because forgotten files are an easy bug bounty find and recon is the first step of every test.

Many sites return 200 for pages that do not exist, so a simple fuzzer reports everything as found. This one first asks for random paths that cannot exist, learns what the "not found" page looks like, and filters those out. A small lab app is included so you can practice on your own machine.

OWASP: this covers A05:2021 Security Misconfiguration and OWASP WSTG-CONF-04 (Review Old Backup and Unreferenced Files for Sensitive Information).

## What it does
- Takes a base URL and a wordlist, and sends GET requests for each word
- Can add extensions like .bak or .zip to every word
- Does not follow redirects, so you see the 301 and where it points
- Checks a few random paths first to find the soft 404 page, and removes matching responses
- Gives each finding a risk: high (.env, .git, backups, phpinfo), medium (admin, config, uploads), low, info
- Refuses to test anything that is not localhost unless you pass `--i-have-permission`
- Wordlist is capped at 2000 words, exit code is 1 when a high risk path is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/24-Directory-Fuzzer

python3 lab_app.py 8000 &
python3 dir_fuzzer.py http://127.0.0.1:8000 --wordlist samples/wordlist.txt
python3 dir_fuzzer.py http://127.0.0.1:8000 --wordlist samples/wordlist.txt --extensions .bak,.zip
```

`samples/targets.txt` has the same commands. The lab app has hidden files like /.env and /config.bak, protected paths like /admin, and a soft 404 on purpose.

## Example
```
$ python3 dir_fuzzer.py http://127.0.0.1:8000 --wordlist samples/wordlist.txt --extensions .bak
Note: this site answers 200 for missing pages. Those were filtered out.

[HIGH  ] 200 /.env                 41 bytes
[HIGH  ] 200 /.git/HEAD            21 bytes
[HIGH  ] 200 /backup.zip          404 bytes
[HIGH  ] 200 /config.bak           43 bytes
[MEDIUM] 401 /admin                23 bytes
[MEDIUM] 403 /uploads               9 bytes
[LOW   ] 200 /robots.txt           53 bytes
[INFO  ] 301 /assets                0 bytes -> /assets/

Tried 39 paths, found 12.
```

## Please read
Use this only on targets you own or have written permission to test. The lab app listens on 127.0.0.1 only. Do not expose it to a network. On a real target with permission, use `--delay` so you do not slow the server down.

## What I'd check in a pentest
- A 401 or 403 still means the path exists, so try other methods and paths under it
- Read robots.txt and sitemap.xml first, they list paths the owner wanted hidden
- If /.git/HEAD is reachable, the whole source code may be downloadable
- Try backup extensions (.bak, .old, .zip, ~) on every real file name you find
- The fix is to remove these files from the web root and block dotfiles in the server config

## Limitations
- It only tests one level, it does not go into folders it finds
- It sends one request at a time, so it is slow on big wordlists
- A soft 404 page that changes on every request (for example it shows the time) may still show up as a finding
- It only uses GET

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
