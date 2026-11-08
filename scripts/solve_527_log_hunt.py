#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Log Hunt (Challenge ID: 527)
Category: General Skills / Log Analysis & Parsing | Difficulty: Easy | Points: 50
Architecture: Chronological Syslog Stream Parsing & Fragmen Assembly (NIST SP 800-115 §4.1)

Reconstructs fragmented flag from timestamp-ordered server logs leaking through excessive INFO logging.
"""

import sys
import os
import re
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 527
CHALLENGE_NAME = "Log Hunt"
LOG_URL = "https://challenge-files.cylabacademy.net/library/fefc39d7d9da79e3c3f78f0d7f12f520ca703a48a89fa1cac6856a5c2127a4e9/server.log"
EXPECTED_FLAG = "academy{us3_y0urlinux_sk1lls_cedfa5fb}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def solve(url=LOG_URL) -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        lines = resp.read().decode("utf-8").splitlines()

    parts = []
    seen = set()
    for line in lines:
        match = re.search(r'FLAGPART:\s*(\S+)', line)
        if match:
            part = match.group(1)
            if part not in seen:
                seen.add(part)
                parts.append(part)
                print(f"[+] Found log fragment: {part}")
            if part.endswith('}'):
                break
    flag = "".join(parts)
    print(f"[+] Reconstructed Flag: {flag}")
    return flag

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
    token = solve()
    assert token == EXPECTED_FLAG, f"Expected {EXPECTED_FLAG}, got {token}"
    submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
