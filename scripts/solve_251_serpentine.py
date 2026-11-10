#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 251: Serpentine (Beginner picoMini 2022)
Category: General Skills / Python Execution & Static Source Reversing
Difficulty: Easy | Points: 50
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 § 4.2 (Static Code Analysis & Source Inspection)
CWE: CWE-798 (Use of Hard-coded Credentials), CWE-670 (Always-False / Unreachable Control Flow Branch), CWE-327 (Broken Cryptographic Algorithm)

Description:
Find the flag in the Python script! Download the script from the CyLab challenge library.
- Script URL: https://challenge-files.cylabacademy.net/library/6f4ff467e583437bc55c9d44497b3c0751e233197567e46d19e87f2887bba4e3/serpentine.py

Vulnerability Analysis & Core Concept:
- Control Flow Branch Misdirection (CWE-670):
  The interactive CLI loop in serpentine.py defines a menu with options 'a', 'b', and 'c'.
  When option 'b' (Print flag) is selected, the application displays a misleading notice:
    "Oops! I must have misplaced the print_flag function! Check my source code!"
  The function print_flag() is fully implemented at the top of the file but is never called
  by any branch in the main loop.
- Client-Side Secret Embedding & Reversible XOR Transformation (CWE-798, CWE-327):
  The ciphertext bytes (flag_enc) and repeating XOR key ("enkidu") are embedded directly
  in the client script source. Reconstructing the str_xor() routine or invoking print_flag()
  statically derives the cleartext token without needing network interactions.

Recovered Flag: academy{7h3_r04d_l355_7r4v3l3d_825b10ae}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import ast
import json
import os
import re
import sys
import urllib.request

CHALLENGE_ID = 251
CHALLENGE_NAME = "Serpentine"
SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/6f4ff467e583437bc55c9d44497b3c0751e233197567e46d19e87f2887bba4e3/serpentine.py"
EXPECTED_FLAG = "academy{7h3_r04d_l355_7r4v3l3d_825b10ae}"

# Embedded ciphertext bytes from serpentine.py for 100% deterministic offline reproduction
EMBEDDED_FLAG_ENC = (
    chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) +
    chr(0x1c) + chr(0x15) + chr(0x5c) + chr(0x01) + chr(0x57) + chr(0x2a) +
    chr(0x17) + chr(0x5e) + chr(0x5f) + chr(0x0d) + chr(0x3b) + chr(0x19) +
    chr(0x56) + chr(0x5b) + chr(0x5e) + chr(0x36) + chr(0x53) + chr(0x07) +
    chr(0x51) + chr(0x18) + chr(0x58) + chr(0x05) + chr(0x57) + chr(0x11) +
    chr(0x3a) + chr(0x56) + chr(0x59) + chr(0x5c) + chr(0x06) + chr(0x44) +
    chr(0x55) + chr(0x0f) + chr(0x0e) + chr(0x14)
)
KEY = "enkidu"


def str_xor(secret: str, key: str) -> str:
    """Reversible repeating XOR stream cipher matching serpentine.py."""
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])


def solve_offline() -> str:
    """Performs deterministic offline XOR decryption of embedded ciphertext."""
    recovered = str_xor(EMBEDDED_FLAG_ENC, KEY)
    assert recovered == EXPECTED_FLAG, f"Flag mismatch: {recovered} vs {EXPECTED_FLAG}"
    return recovered


def solve(script_path: str | None = None) -> str:
    """Performs deterministic offline XOR decryption of embedded ciphertext."""
    return solve_offline()


def submit_to_cylab(token: str) -> bool:
    """Direct live platform submission gate."""
    sys.path.insert(0, "/tmp")
    try:
        import cylab_auth
        status, body = cylab_auth.req(
            "https://learn.cylabacademy.org/api/submissions/",
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        data = json.loads(body)
        return (status == 201 and data.get("correct") is True)
    except Exception as e:
        print(f"[-] Live submission check failed: {e}")
        return False


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(p)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
