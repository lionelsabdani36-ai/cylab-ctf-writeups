#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 245: PW Crack 1 (Beginner picoMini 2022)
Category: General Skills / Static Code Inspection & Hardcoded Credentials
Difficulty: Easy | Points: 25
Standard Reference: NIST SP 800-115 Section 4.2 (Static Source Code Review & Password Analysis)
CWE: CWE-259 (Use of Hard-coded Password), CWE-798 (Use of Hard-coded Credentials)

Description:
Can you crack the password to get the flag? Download the password checker level1.py
and the encrypted flag level1.flag.txt.enc in the same directory.
- Script: https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.py
- Encrypted Flag: https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.flag.txt.enc

Vulnerability Analysis & Core Concept:
- The script checks user password input using direct equality comparison against a hardcoded string literal:
    if (user_pw == "1e1a"):
- In insecure software development, hardcoding credentials directly in client-side scripts exposes
  the authentication token to trivial static inspection.
- The decryption function str_xor executes modular key-extension XOR against the ciphertext bytes
  using the hardcoded password string as the symmetric key.

Recovered Flag: academy{545h_r1ng1ng_4a96bf39}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import os
import sys
import urllib.request

SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.py"
ENC_FLAG_URL = "https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.flag.txt.enc"
HARDCODED_PW = "1e1a"
EXPECTED_FLAG = "academy{545h_r1ng1ng_4a96bf39}"
EMBEDDED_ENC = b"P\x06P\x05T\x08H\x1a\x04Q\x04\tn\x17\x00\x0fVT_\x06nQPX\x07\x07WR\x08\x18"


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
    elif os.path.exists("level1.flag.txt.enc"):
        with open("level1.flag.txt.enc", "rb") as f:
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

    flag = str_xor(enc_data.decode("latin-1", errors="ignore"), HARDCODED_PW)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    enc_path = sys.argv[1] if len(sys.argv) > 1 else None
    recovered = solve(enc_path)
    print(f"[+] Recovered Password: {HARDCODED_PW}")
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
