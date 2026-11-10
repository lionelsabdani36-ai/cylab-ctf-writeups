#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 246: PW Crack 2 (Beginner picoMini 2022)
Category: General Skills / Static Code Analysis & Hex-Encoded Hardcoded Credentials
Difficulty: Easy | Points: 35
Standard Reference: NIST SP 800-115 Section 4.2 (Static Source Code Review & Deobfuscation)
CWE: CWE-259 (Use of Hard-coded Password), CWE-798 (Use of Hard-coded Credentials)

Description:
Can you crack the password to get the flag? Download the password checker level2.py
and the encrypted flag level2.flag.txt.enc in the same directory.
- Script: https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.py
- Encrypted Flag: https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.flag.txt.enc

Vulnerability Analysis & Core Concept:
- The script checks user password input using an obfuscated expression:
    if (user_pw == chr(0x64) + chr(0x65) + chr(0x37) + chr(0x36)):
- Evaluating the chr() hexadecimal ordinals:
    - 0x64 = 100 -> 'd'
    - 0x65 = 101 -> 'e'
    - 0x37 = 55  -> '7'
    - 0x36 = 54  -> '6'
  Yields the plaintext password: "de76".
- Obfuscating secrets with trivial character ordinals provides zero cryptographic security.
- Decrypting level2.flag.txt.enc with str_xor and key "de76" recovers the flag.

Recovered Flag: academy{tr45h_51ng1ng_ab548076}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import os
import sys
import urllib.request

SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.py"
ENC_FLAG_URL = "https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.flag.txt.enc"
RESOLVED_PW = chr(0x64) + chr(0x65) + chr(0x37) + chr(0x36)  # "de76"
EXPECTED_FLAG = "academy{tr45h_51ng1ng_ab548076}"
EMBEDDED_ENC = b"\x05\x06VR\x01\x08NM\x10\x17\x03\x03\x0c:\x02\x07\n\x02\x06X\x03:VTQQ\x0f\x06SSJ"


def str_xor(secret: str, key: str) -> str:
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])


def solve(enc_file_path: str | None = None) -> str:
    enc_data = None
    if enc_file_path and os.path.exists(enc_file_path):
        with open(enc_file_path, "rb") as f:
            enc_data = f.read()
    elif os.path.exists("level2.flag.txt.enc"):
        with open("level2.flag.txt.enc", "rb") as f:
            enc_data = f.read()
    else:
        try:
            req = urllib.request.Request(ENC_FLAG_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                enc_data = resp.read()
        except Exception:
            enc_data = EMBEDDED_ENC

    if not enc_data:
        enc_data = EMBEDDED_ENC

    flag = str_xor(enc_data.decode("latin-1", errors="ignore"), RESOLVED_PW)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    enc_path = sys.argv[1] if len(sys.argv) > 1 else None
    recovered = solve(enc_path)
    print(f"[+] Recovered Password: {RESOLVED_PW}")
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
