#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 7: vault-door-training (picoCTF 2019)
Category: Reverse Engineering / Java Source Code Static Analysis
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Section 5.3: Source Code Review & Static Analysis)
CWE: CWE-798 (Use of Hard-coded Credentials), CWE-259 (Use of Hard-coded Password)

Description:
Your mission is to enter Dr. Evil's laboratory and retrieve the blueprints for his Doomsday Project.
The laboratory is protected by a series of locked vault doors. Each door is controlled by a computer
and requires a password to open... You will need to read the source code for each level to figure out
what the password is. As a warmup, we have created a replica vault in our training facility.

Methodology:
- Static analysis of Java source code VaultDoorTraining.java.
- The checkPassword method directly evaluates string equality against a hardcoded constant:
  password.equals("w4rm1ng_Up_w1tH_jAv4_8352733cecd")
- The wrapper logic strips "academy{" prefix and trailing "}" from the user input.
- Recovered flag: academy{w4rm1ng_Up_w1tH_jAv4_8352733cecd}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/78ec91618d4c4219c55fbe2c9fc67ec6e248664564e6b2f13a54534aaf1d1000/VaultDoorTraining.java"
EXPECTED_FLAG = "academy{w4rm1ng_Up_w1tH_jAv4_8352733cecd}"


def solve(file_path: str | None = None) -> str:
    code = ""
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    elif os.path.exists("VaultDoorTraining.java"):
        with open("VaultDoorTraining.java", "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    elif os.path.exists("/tmp/VaultDoorTraining.java"):
        with open("/tmp/VaultDoorTraining.java", "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            code = resp.read().decode("utf-8", errors="ignore")

    m = re.search(r'password\.equals\(\"([^\"]+)\"\)', code)
    if not m:
        raise ValueError("Password equality check not found in Java source")

    inner_pw = m.group(1)
    flag = f"academy{{{inner_pw}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
