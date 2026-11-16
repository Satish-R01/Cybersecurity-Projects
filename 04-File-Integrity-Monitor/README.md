# File Integrity Monitor

Python script that takes a SHA-256 baseline of a folder and later tells you which files were modified, added, deleted or had their permissions changed. I made it to understand how tools like AIDE or Tripwire work.

## What it does
- Walks a directory and saves SHA-256, size and permissions of every file to baseline.json
- On check, compares the folder with the baseline
- Reports MODIFIED, NEW, DELETED and PERMISSION changes
- Exit code is 1 when something changed, so it can be used in a cron job
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/04-File-Integrity-Monitor

python3 fim.py baseline sample_dir
python3 fim.py check sample_dir
python3 fim.py baseline /etc -o etc_baseline.json
sudo python3 fim.py check /etc -b etc_baseline.json
```

## Output on the sample folder
I took a baseline, then copied the folder and changed it like an attacker would (edited sshd_config, dropped a php shell, deleted app.py, chmod 777 on passwd).
```
$ python3 fim.py baseline sample_dir
Baseline saved: 4 files -> /tmp/b.json

(then an attacker edits sshd_config, adds a backdoor, deletes app.py)
$ python3 fim.py check sample_dir
[!] 4 change(s) found
PERMISSION  conf/passwd
MODIFIED    conf/sshd_config
DELETED     web/app.py
NEW         web/shell.php
```

The sample folder is a few fake config and web files.

## What I'd do as L1 after an alert
- Check if the change was planned (patching, a change ticket). If not, escalate
- NEW file in a web folder (like shell.php) looks like a web shell, isolate the server and escalate to L2
- MODIFIED config such as sshd_config or passwd, compare with a known good copy and check who logged in
- Keep the baseline on a different, read-only place, otherwise the attacker can edit it too

MITRE ATT&CK: T1565.001 Stored Data Manipulation, T1505.003 Web Shell, T1222 File Permissions Modification.

## Limitations
- It only checks when you run it, it is not real-time
- Does not follow symlinks

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
