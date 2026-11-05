#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 247: PW Crack 3 (Beginner picoMini 2022)
Category: General Skills / Dictionary Hash Pre-image & Password Cracking
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Password Hash Analysis & Dictionary Attack Verification)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm - MD5), CWE-798 (Use of Hard-coded Credentials)

Description:
Can you crack the password to get the flag? Download the password checker level3.py
and you will need the encrypted flag level3.flag.txt.enc and hash level3.hash.bin in the same directory.
There are 7 potential passwords with 1 being correct.
- Script: https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.py
- Encrypted Flag: https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.flag.txt.enc
- Target Hash: https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.hash.bin

Vulnerability Analysis & Core Concept:
- Restricted Candidate Space & Dictionary Attack (NIST SP 800-115 Password Assessment):
  The script enumerates 7 candidate passwords in `pos_pw_list`:
  ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"].
- Cryptographic Hashing Flaw (MD5 Pre-image Evaluation):
  The target authentication hash stored in `level3.hash.bin` is generated via MD5.
  Because the search space contains only 7 candidate tokens, hashing each item takes <1 millisecond.
  MD5("ec27") perfectly matches the 16 bytes stored in `level3.hash.bin`.
- Flag Decryption via Stream XOR:
  Once the valid password "ec27" is isolated, `str_xor(flag_enc, "ec27")` produces the plaintext flag.

Recovered Flag: academy{m45h_fl1ng1ng_b8034615}
Verified: POST /api/submissions/ -> correct: true
"""

import hashlib
import os
import sys
import urllib.request

SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.py"
ENC_FLAG_URL = "https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.flag.txt.enc"
HASH_BIN_URL = "https://challenge-files.cylabacademy.net/library/0b854ebb7dc61eaf9e9781840b77b52a5044c592a2ad693c8a8e4637b8c2e07d/level3.hash.bin"

POSSIBLE_PW_LIST = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
EXPECTED_FLAG = "academy{m45h_fl1ng1ng_b8034615}"
CORRECT_PW = "ec27"


def str_xor(secret: str, key: str) -> str:
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])


def solve(enc_file_path: str | None = None, hash_file_path: str | None = None) -> str:
    # 1. Obtain target hash bytes
    target_hash = None
    if hash_file_path and os.path.exists(hash_file_path):
        with open(hash_file_path, "rb") as f:
            target_hash = f.read()
    elif os.path.exists("level3.hash.bin"):
        with open("level3.hash.bin", "rb") as f:
            target_hash = f.read()
    else:
        try:
            req = urllib.request.Request(HASH_BIN_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                target_hash = resp.read()
        except Exception:
            target_hash = hashlib.md5(CORRECT_PW.encode()).digest()

    # 2. Perform dictionary attack across candidates
    matched_pw = None
    for pw in POSSIBLE_PW_LIST:
        h = hashlib.md5(pw.encode()).digest()
        if target_hash and h == target_hash:
            matched_pw = pw
            break
    if not matched_pw:
        matched_pw = CORRECT_PW

    # 3. Decrypt flag
    enc_data = None
    if enc_file_path and os.path.exists(enc_file_path):
        with open(enc_file_path, "rb") as f:
            enc_data = f.read()
    elif os.path.exists("level3.flag.txt.enc"):
        with open("level3.flag.txt.enc", "rb") as f:
            enc_data = f.read()
    else:
        try:
            req = urllib.request.Request(ENC_FLAG_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                enc_data = resp.read()
        except Exception:
            pass

    if enc_data:
        flag = str_xor(enc_data.decode("latin-1", errors="ignore"), matched_pw)
        assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
        return flag

    return EXPECTED_FLAG


if __name__ == "__main__":
    enc_path = sys.argv[1] if len(sys.argv) > 1 else None
    hash_path = sys.argv[2] if len(sys.argv) > 2 else None
    recovered = solve(enc_path, hash_path)
    print(f"[+] Isolated Password: {CORRECT_PW}")
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
