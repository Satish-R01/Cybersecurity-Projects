#!/usr/bin/env python3
"""Check a JSON Web Token for common security problems.

Reads a JWT and looks for the mistakes that come up a lot in web apps:
alg none, weak HMAC secrets, no expiry, already expired, long lifetime,
and a few others. It only reads the token and an optional secret wordlist,
it does not talk to any server. Only the Python standard library is used.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import time


def b64url_decode(part):
    """Decode a base64url string, adding padding if it is missing."""
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def split_token(token):
    """Split a token into (header, payload, signature) strings. Raises ValueError."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token does not have 3 parts separated by '.'")
    return parts[0], parts[1], parts[2]


def decode_part(part):
    """Decode a base64url JSON part into a dict. Raises ValueError on bad data."""
    try:
        raw = b64url_decode(part)
    except Exception as exc:
        raise ValueError("part is not valid base64url: %s" % exc)
    try:
        return json.loads(raw)
    except Exception as exc:
        raise ValueError("part is not valid JSON: %s" % exc)


def verify_hs256(token, secret):
    """Return True if the HS256/384/512 signature matches the given secret."""
    header_b64, payload_b64, sig_b64 = split_token(token)
    header = decode_part(header_b64)
    alg = header.get("alg", "").upper()
    hashes = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in hashes:
        return False
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    expected = hmac.new(secret, signing_input, hashes[alg]).digest()
    try:
        given = b64url_decode(sig_b64)
    except Exception:
        return False
    return hmac.compare_digest(expected, given)


def crack_secret(token, words):
    """Try each word as the HMAC secret. Return the first that verifies, or None."""
    for word in words:
        word = word.rstrip("\n")
        if not word:
            continue
        if verify_hs256(token, word):
            return word
    return None


def forge_alg_none(token):
    """Make an alg:none version of the token with an empty signature."""
    header_b64, payload_b64, _ = split_token(token)
    header = decode_part(header_b64)
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return new_header + "." + payload_b64 + "."


def analyse(token, words=None, now=None):
    """Look at a token and return a list of findings.

    Each finding is a dict: id, severity (HIGH/MEDIUM/LOW/INFO) and message.
    """
    if now is None:
        now = int(time.time())
    findings = []

    def add(fid, severity, message):
        findings.append({"id": fid, "severity": severity, "message": message})

    header_b64, payload_b64, sig_b64 = split_token(token)
    header = decode_part(header_b64)
    payload = decode_part(payload_b64)

    alg = str(header.get("alg", "")).strip()
    alg_u = alg.upper()

    # alg none
    if alg_u in ("NONE", ""):
        add("alg_none", "HIGH",
            "Header uses alg '%s'. A server that accepts this trusts a token with no "
            "signature, so anyone can change the payload." % (alg or "(empty)"))
    elif alg_u.startswith("HS"):
        add("alg_hmac", "INFO", "Signed with HMAC (%s), a shared secret." % alg)
    elif alg_u.startswith(("RS", "ES", "PS")):
        add("alg_asym", "INFO", "Signed with asymmetric key (%s)." % alg)
        add("alg_confusion", "MEDIUM",
            "Asymmetric alg in use. Test if the server also accepts the same token "
            "re-signed as HS256 using the public key as the secret (alg confusion).")
    else:
        add("alg_unknown", "MEDIUM", "Unusual alg '%s'. Check what the server accepts." % alg)

    # signature present
    if sig_b64 == "":
        add("empty_sig", "HIGH", "Signature part is empty. The token is not signed.")

    # expiry
    if "exp" not in payload:
        add("no_exp", "MEDIUM",
            "No 'exp' claim. The token never expires, so a stolen token works forever.")
    else:
        try:
            exp = int(payload["exp"])
            if exp < now:
                add("expired", "LOW",
                    "Token expired at %s (%d seconds ago)."
                    % (time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(exp)), now - exp))
            else:
                life_left = exp - now
                if "iat" in payload:
                    try:
                        total = exp - int(payload["iat"])
                        if total > 24 * 3600:
                            add("long_life", "LOW",
                                "Token lifetime is %d hours. Long-lived tokens are harder "
                                "to revoke." % (total // 3600))
                    except (ValueError, TypeError):
                        pass
                add("valid_time", "INFO",
                    "Token is still valid for %d minutes." % (life_left // 60))
        except (ValueError, TypeError):
            add("bad_exp", "MEDIUM", "'exp' claim is not a number.")

    # not before / issued at sanity
    if "nbf" in payload:
        try:
            if int(payload["nbf"]) > now:
                add("not_yet_valid", "INFO", "Token's 'nbf' is in the future, not valid yet.")
        except (ValueError, TypeError):
            pass

    # sensitive data in payload
    sensitive = ("password", "pwd", "secret", "ssn", "credit", "card", "cvv", "pin")
    for key in payload:
        if any(s in str(key).lower() for s in sensitive):
            add("sensitive_claim", "MEDIUM",
                "Claim '%s' may hold sensitive data. The payload is only base64, "
                "anyone can read it." % key)

    # missing kid when asymmetric (common for key rotation issues) - informational
    if alg_u.startswith(("RS", "ES", "PS")) and "kid" not in header:
        add("no_kid", "LOW", "No 'kid' in header. Key rotation and selection may be unclear.")

    # weak secret crack for HMAC tokens
    if alg_u.startswith("HS") and words:
        found = crack_secret(token, words)
        if found is not None:
            add("weak_secret", "HIGH",
                "The HMAC secret is a common/weak value: '%s'. Anyone who guesses it "
                "can sign tokens as any user." % found)
        else:
            add("secret_not_found", "INFO",
                "Secret was not in the wordlist (%d words tried)." % len(words))

    return {"header": header, "payload": payload, "findings": findings}


SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def print_report(result):
    findings = sorted(result["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 9))
    print("Header:  " + json.dumps(result["header"], separators=(", ", ": ")))
    print("Payload: " + json.dumps(result["payload"], separators=(", ", ": ")))
    print()
    high = sum(1 for f in findings if f["severity"] in ("HIGH", "MEDIUM"))
    print("[!] %d finding(s), %d need attention" % (len(findings), high))
    for f in findings:
        print("  %-7s %-16s %s" % (f["severity"], f["id"], f["message"]))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check a JWT for common security problems.")
    parser.add_argument("token", nargs="?", help="the JWT, or '-' to read from stdin")
    parser.add_argument("-w", "--wordlist", help="file of secrets to try on HMAC tokens")
    parser.add_argument("--forge-none", action="store_true",
                        help="print an alg:none version of the token and exit")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args(argv)

    if not args.token or args.token == "-":
        token = sys.stdin.read().strip()
    else:
        token = args.token

    if not token:
        parser.error("no token given")

    try:
        split_token(token)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if args.forge_none:
        print(forge_alg_none(token))
        return 0

    words = None
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            words = fh.read().splitlines()

    try:
        result = analyse(token, words=words)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)

    has_problem = any(f["severity"] in ("HIGH", "MEDIUM") for f in result["findings"])
    return 1 if has_problem else 0


if __name__ == "__main__":
    sys.exit(main())
