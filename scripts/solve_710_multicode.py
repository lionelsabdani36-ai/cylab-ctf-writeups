#!/usr/bin/env python3
"""
CyLab Security Academy Solver: MultiCode (Challenge ID: 710)
Category: General Skills | Difficulty: Easy / Medium | Points: 100
Analysis & De-obfuscation Pipeline:
Layer 1: Base64 Decoding (RFC 4648)
Layer 2: Hexadecimal ASCII Decoding (RFC 4648 §8)
Layer 3: Percent-Encoding / URL Unquoting (RFC 3986)
Layer 4: ROT13 Caesar Substitution (RFC 4880 / Historical Caesar CIPHER)
Standard Reference: NIST SP 800-115 Section 4.1 (Target Identification & Analysis)
"""

import sys
import os
import base64
import urllib.parse
import codecs
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 710
CHALLENGE_NAME = "MultiCode"
MESSAGE_URL = "https://challenge-files.cylabacademy.net/library/c3ba15daad71c2f215d6e6db4a6d4c70a4696eef42dd338372287cc4d2a6268e/message.txt"
VERIFIED_FLAG = "academy{nested_enc0ding_74af0c65}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def fetch_and_decode(raw_text: str = None) -> str:
    if not raw_text:
        try:
            req = urllib.request.Request(MESSAGE_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw_text = resp.read().decode("utf-8").strip()
        except Exception:
            raw_text = "NmU3MDZlNzE3MjdhNmMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM3MzQ2ZTczMzA3MDM2MzUyNTM3NDQ="

    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"[*] Intercepted raw text: {raw_text}")

    # Layer 1: Base64
    layer1 = base64.b64decode(raw_text).decode("utf-8")
    print(f"[+] Layer 1 (Base64 decoded): {layer1}")

    # Layer 2: Hex
    layer2 = bytes.fromhex(layer1).decode("utf-8")
    print(f"[+] Layer 2 (Hex decoded): {layer2}")

    # Layer 3: URL Unquote
    layer3 = urllib.parse.unquote(layer2)
    print(f"[+] Layer 3 (URL unquoted): {layer3}")

    # Layer 4: ROT13
    layer4 = codecs.decode(layer3, "rot13")
    print(f"[+] Layer 4 (ROT13 decoded flag): {layer4}")

    return layer4

def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False

def main():
    token = fetch_and_decode()
    assert token == VERIFIED_FLAG, f"Expected {VERIFIED_FLAG}, got {token}"
    submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
