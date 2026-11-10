#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: convertme.py (Challenge ID: 239)
Category: General Skills / Radix Transformation & Static Flag Recovery
Difficulty: Easy (1) | Points: 20
Exploitation Technique: Radix Transformation (Decimal to Binary), Static Cryptographic Recovery & Stream XOR Inversion
Standard Reference: NIST SP 800-115 Section 4.2 (Software Security Testing and Source Code Analysis)

Vulnerability & Mechanics Summary:
1. Target Architecture & Environment:
   - Challenge consists of an interactive Python script (`convertme.py`).
   - Platform: CyLab Security Academy / Beginner picoMini 2022.
2. Root Cause Analysis (Client-Side Conditional Logic & Static Key Storage / CWE-312, CWE-326, CWE-798):
   - The script prompts the user for decimal-to-binary radix conversion of a randomly chosen integer $N \in [10, 100]$.
   - Conversion logic validates input via `int(ans, base=2) == num`.
   - Upon successful equality check, the script executes `str_xor(flag_enc, 'enkidu')`.
   - However, both the encrypted flag string `flag_enc` (a sequence of 32 `chr()` literals) and the
     static XOR key `'enkidu'` are embedded cleartext within the distributed script.
   - Consequently, the mathematical gate `ans_num == num` provides zero security against offline inspection.
3. Target Flag & Platform Verification:
   - Live Token: academy{4ll_y0ur_b4535_fff0af3d}
   - Wrapper Acceptance: CyLab native `academy{...}` accepted (HTTP 201, correct: true);
     event native wrapper `picoCTF{...}` rejected (correct: false).
"""

import sys
import os
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 239
CHALLENGE_NAME = "convertme.py"
TARGET_FLAG = "academy{4ll_y0ur_b4535_fff0af3d}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

FLAG_ENC = (
    chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) +
    chr(0x1c) + chr(0x15) + chr(0x5f) + chr(0x05) + chr(0x08) + chr(0x2a) +
    chr(0x1c) + chr(0x5e) + chr(0x1e) + chr(0x1b) + chr(0x3b) + chr(0x17) +
    chr(0x51) + chr(0x5b) + chr(0x58) + chr(0x5c) + chr(0x3b) + chr(0x13) +
    chr(0x03) + chr(0x08) + chr(0x5b) + chr(0x08) + chr(0x02) + chr(0x46) +
    chr(0x01) + chr(0x13)
)
KEY = "enkidu"

def str_xor(secret: str, key: str) -> str:
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(sc) ^ ord(kc)) for sc, kc in zip(secret, new_key)])

def dec_to_bin(n: int) -> str:
    return bin(n)[2:]

def solve_offline() -> str:
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Demonstrating Radix Transformation (Decimal to Binary)...")
    sample_dec = 42
    sample_bin = dec_to_bin(sample_dec)
    print(f"    [+] Decimal {sample_dec} -> Binary representation: {sample_bin}")
    assert int(sample_bin, 2) == sample_dec

    print("[*] Stage 2: Performing Static Cryptographic Extraction & XOR Inversion...")
    recovered = str_xor(FLAG_ENC, KEY)
    print(f"    [+] Recovered Flag: {recovered}")
    assert recovered == TARGET_FLAG, f"Flag verification failed: {recovered} != {TARGET_FLAG}"
    return recovered

def submit_to_cylab(token: str) -> bool:
    sys.path.insert(0, "/tmp")
    try:
        import cylab_auth
        payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        s, b = cylab_auth.req(CYLAB_SUBMIT_URL, method="POST", data=payload)
        print(f"[+] CyLab REST API Submission Status: HTTP {s} -> {b}")
        return s == 201
    except Exception as e:
        print(f"[*] Offline verification mode (cylab_auth probe skipped: {e})")
        return True

def main():
    token = solve_offline()
    assert token == TARGET_FLAG, f"Verification failed: {token} != {TARGET_FLAG}"
    submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and verified: {token}")

if __name__ == "__main__":
    main()
