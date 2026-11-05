#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 166: Python Wrangling (picoCTF 2021)
Category: General Skills / Python Execution & Fernet Symmetric Decryption
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Cryptographic & Key Management Analysis)
CWE: CWE-321 (Use of Hard-coded Cryptographic Key / Password)

Description:
Python scripts are invoked kind of like programs in the Terminal...
Can you run ende.py using password.txt to get flag.txt.en?

Methodology:
- Challenge provides:
  1. ende.py (utility script utilizing cryptography.fernet.Fernet)
  2. password.txt containing plaintext password '563e47ddeaf84eca8b2a31201381a898'
  3. flag.txt.en containing Fernet-encrypted ciphertext token
- In ende.py:
  Fernet key is derived via base64 encoding the raw password string:
  key = base64.b64encode(password.encode())
- Initializing Fernet(key).decrypt(ciphertext) decrypts the payload and recovers:
  academy{4p0110_1n_7h3_h0us3_d6af8f37}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import base64
import os
import sys
import urllib.request
from cryptography.fernet import Fernet

BASE_URL = "https://challenge-files.cylabacademy.net/library/1f8bb290392a5ab6795ba98cf621ec507bd52be282f62f32e35c43e0d7fc2415/"
EXPECTED_FLAG = "academy{4p0110_1n_7h3_h0us3_d6af8f37}"


def fetch_or_read(filename: str, local_path: str | None = None) -> bytes:
    if local_path and os.path.exists(local_path):
        with open(local_path, "rb") as f:
            return f.read()
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            return f.read()
    url = BASE_URL + filename
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://learn.cylabacademy.org/challenges",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def solve(dir_path: str | None = None) -> str:
    pw_path = os.path.join(dir_path, "password.txt") if dir_path else None
    flag_path = os.path.join(dir_path, "flag.txt.en") if dir_path else None

    password_raw = fetch_or_read("password.txt", pw_path).decode().strip()
    flag_enc = fetch_or_read("flag.txt.en", flag_path).strip()

    # Fernet symmetric decryption
    key = base64.b64encode(password_raw.encode())
    fernet = Fernet(key)
    decrypted_bytes = fernet.decrypt(flag_enc)
    flag = decrypted_bytes.decode("utf-8").strip()

    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else None
    recovered_flag = solve(target_dir)
    print(f"[+] Recovered Flag: {recovered_flag}")
    assert recovered_flag == EXPECTED_FLAG
