# JWT Security Tester

Python script that reads a JSON Web Token and flags the security mistakes that come up a lot in web apps: alg none, weak HMAC secrets, no expiry, long lifetime and a few more. I made it while learning web application penetration testing, because JWTs are used for auth in almost every API now and getting them wrong is a common bug bounty finding.

It only reads the token and an optional secret wordlist. It does not send anything to any server.

OWASP: this covers A07:2021 Identification and Authentication Failures, and the token checks in OWASP WSTG-SESS-10 (Testing JSON Web Tokens).

## What it does
- Splits the token and base64url-decodes the header and payload (the payload is not secret, anyone can read it)
- Flags `alg: none`, which lets anyone send an unsigned token the server may still trust
- Tries a wordlist of common secrets against HMAC (HS256/384/512) tokens and reports the first one that verifies
- Flags a missing `exp`, an already expired token and a very long lifetime
- Flags claims that look like they hold a password or other sensitive data
- Notes asymmetric tokens (RS/ES/PS) and reminds you to test alg confusion (re-signing with the public key as an HMAC secret)
- `--forge-none` prints an `alg: none` copy of the token so you can test the server
- Exit code is 1 when something needs attention, `--json` gives JSON output
- Only uses the Python standard library

## How to run
```
git clone https://github.com/Satish-R01/Cybersecurity-Projects.git
cd Cybersecurity-Projects/07-JWT-Security-Tester

python3 jwt_tester.py <token>
python3 jwt_tester.py <token> -w samples/secrets.txt
python3 jwt_tester.py <token> --json
python3 jwt_tester.py <token> --forge-none
```

`samples/tokens.txt` has five example tokens (one per non-comment line) and `samples/secrets.txt` is a small secret wordlist.

## Example
```
$ python3 jwt_tester.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0Ii... -w samples/secrets.txt
Header:  {"alg": "HS256", "typ": "JWT"}
Payload: {"sub": "1234", "name": "Alice", "role": "user"}

[!] 3 finding(s), 2 need attention
  HIGH    weak_secret      The HMAC secret is a common/weak value: 'secret'. Anyone who guesses it can sign tokens as any user.
  MEDIUM  no_exp           No 'exp' claim. The token never expires, so a stolen token works forever.
  INFO    alg_hmac         Signed with HMAC (HS256), a shared secret.
```

When the secret is weak, the next step is to forge a token with any user or role and send it to the server:
```
$ python3 jwt_tester.py <token> --forge-none
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0Ii...
```

## Please read
Use this only on tokens from an app you own or have written permission to test. Cracking a secret and forging a token against a live system you do not own is illegal. The sample tokens here are made up for practice.

## What I'd check in a pentest
- Change the payload (user id, role, admin flag) and see if the server still accepts the token. If it does, the signature is not being checked
- Send an `alg: none` version and see if it is accepted
- If it is HMAC, try weak secrets. A guessed secret means you can sign tokens as anyone
- If it is RS256, try re-signing as HS256 with the server's public key as the secret (alg confusion)
- Check `exp`. No expiry or a very long one means a stolen token lives too long
- Read the payload. Secrets or passwords should never be in there

## Limitations
- The weak-secret check is only as good as the wordlist
- It does not verify RS/ES signatures (no public key is given), it only reads them
- The base domain and claim checks are simple, not a full RFC 7519 validator

## Tests
```
pip install pytest
python3 -m pytest tests
```

Satish R - https://www.linkedin.com/in/cybersatish
