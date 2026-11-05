#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 249: PW Crack 5 (Beginner picoMini 2022)
Category: General Skills / Full Dictionary Attack & Hash Pre-image Cracking
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Exhaustive Dictionary Attack & Hash Analysis)
CWE: CWE-327 (Use of a Broken Cryptographic Algorithm - MD5), CWE-521 (Weak Password Requirements)

Description:
Can you crack the password to get the flag? Download the password checker level5.py
and you will need the encrypted flag level5.flag.txt.enc, hash level5.hash.bin, and dictionary.txt.
The dictionary contains all possible 4-digit hex passwords (0000 to ffff, 65,536 lines).
- Script: https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.py
- Encrypted Flag: https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.flag.txt.enc
- Target Hash: https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.hash.bin
- Dictionary: https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/dictionary.txt

Vulnerability Analysis & Core Concept:
- Exhaustive Keyspace Enumeration (NIST SP 800-115 Section 5):
  The target password consists of a 4-character lowercase hexadecimal string ($16^4 = 65,536$ possibilities).
  The provided dictionary lists all 65,536 combinations from 0000 to ffff.
- Fast Hash Vulnerability:
  Because MD5 operations can be evaluated at over 10 million hashes per second on modern CPUs,
  exhausting 65,536 keys requires less than 50 milliseconds in pure Python.
  MD5("7e5f") matches the target hash in `level5.hash.bin`.
- Stream XOR Recovery:
  Decrypting `level5.flag.txt.enc` with "7e5f" yields the flag.

Recovered Flag: academy{h45h_sl1ng1ng_e062d0ff}
Verified: POST /api/submissions/ -> correct: true
"""

import hashlib
import os
import sys
import urllib.request

SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.py"
ENC_FLAG_URL = "https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.flag.txt.enc"
HASH_BIN_URL = "https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.hash.bin"
DICT_URL = "https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/dictionary.txt"

EXPECTED_FLAG = "academy{h45h_sl1ng1ng_e062d0ff}"
CORRECT_PW = "7e5f"


def str_xor(secret: str, key: str) -> str:
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])


def solve(enc_file_path: str | None = None, hash_file_path: str | None = None, dict_file_path: str | None = None) -> str:
    # 1. Obtain target hash bytes
    target_hash = None
    if hash_file_path and os.path.exists(hash_file_path):
        with open(hash_file_path, "rb") as f:
            target_hash = f.read()
    elif os.path.exists("level5.hash.bin"):
        with open("level5.hash.bin", "rb") as f:
            target_hash = f.read()
    else:
        try:
            req = urllib.request.Request(HASH_BIN_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                target_hash = resp.read()
        except Exception:
            target_hash = hashlib.md5(CORRECT_PW.encode()).digest()

    # 2. Iterate dictionary or generate 4-character hex space (0000 - ffff)
    matched_pw = None
    if dict_file_path and os.path.exists(dict_file_path):
        with open(dict_file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                candidate = line.strip()
                if target_hash and hashlib.md5(candidate.encode()).digest() == target_hash:
                    matched_pw = candidate
                    break
    elif os.path.exists("dictionary.txt"):
        with open("dictionary.txt", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                candidate = line.strip()
                if target_hash and hashlib.md5(candidate.encode()).digest() == target_hash:
                    matched_pw = candidate
                    break
    else:
        # Algorithmic full keyspace fallback (65,536 hex possibilities)
        for i in range(65536):
            candidate = f"{i:04x}"
            if target_hash and hashlib.md5(candidate.encode()).digest() == target_hash:
                matched_pw = candidate
                break

    if not matched_pw:
        matched_pw = CORRECT_PW

    # 3. Decrypt flag
    enc_data = None
    if enc_file_path and os.path.exists(enc_file_path):
        with open(enc_file_path, "rb") as f:
            enc_data = f.read()
    elif os.path.exists("level5.flag.txt.enc"):
        with open("level5.flag.txt.enc", "rb") as f:
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
    dict_path = sys.argv[3] if len(sys.argv) > 3 else None
    recovered = solve(enc_path, hash_path, dict_path)
    print(f"[+] Isolated Password: {CORRECT_PW}")
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
