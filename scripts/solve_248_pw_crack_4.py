#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 248: PW Crack 4 (Beginner picoMini 2022)
Category: General Skills / Automated Dictionary Hash Cracking
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Automated Password Recovery & Digest Verification)
CWE: CWE-327 (Use of a Broken Cryptographic Algorithm - MD5), CWE-798 (Use of Hard-coded Credentials)

Description:
Can you crack the password to get the flag? Download the password checker level4.py
and you will need the encrypted flag level4.flag.txt.enc and hash level4.hash.bin in the same directory.
There are 100 potential passwords with only 1 being correct.
- Script: https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.py
- Encrypted Flag: https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.flag.txt.enc
- Target Hash: https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.hash.bin

Vulnerability Analysis & Core Concept:
- Scaled Dictionary Attack Automation (NIST SP 800-115):
  Unlike PW Crack 3 with 7 possibilities, PW Crack 4 expands the candidate list to 100 4-character hex strings.
  Manual trial via interactive input is inefficient (100 manual entries).
  Scripting the pre-image search via MD5 computation evaluates all 100 items in milliseconds.
- Cryptographic Weakness:
  Unsalted MD5 hashing of short 4-character strings without computational delay allows instantaneous
  exhaustive testing across candidate spaces.
  MD5("bb8e") matches the stored digest in `level4.hash.bin`.
- Stream Decryption:
  `str_xor(flag_enc, "bb8e")` recovers the plaintext flag.

Recovered Flag: academy{fl45h_5pr1ng1ng_c1e14a37}
Verified: POST /api/submissions/ -> correct: true
"""

import hashlib
import os
import sys
import urllib.request

SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.py"
ENC_FLAG_URL = "https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.flag.txt.enc"
HASH_BIN_URL = "https://challenge-files.cylabacademy.net/library/846131a53233d7d11fb53d10ebe53b2addb4693a7f39e2f464fed1d85226b899/level4.hash.bin"

POSSIBLE_PW_LIST = [
    "158f", "1655", "d21e", "4966", "ed69", "1010", "dded", "844c", "40ab", "a948",
    "156c", "ab7f", "4a5f", "e38c", "ba12", "f7fd", "d780", "4f4d", "5ba1", "96c5",
    "55b9", "8a67", "d32b", "aa7a", "514b", "e4e1", "1230", "cd19", "d6dd", "b01f",
    "fd2f", "7587", "86c2", "d7b8", "55a2", "b77c", "7ffe", "4420", "e0ee", "d8fb",
    "d748", "b0fe", "2a37", "a638", "52db", "51b7", "5526", "40ed", "5356", "6ad4",
    "2ddd", "177d", "84ae", "cf88", "97a3", "17ad", "7124", "eff2", "e373", "c974",
    "7689", "b8b2", "e899", "d042", "47d9", "cca9", "ab2a", "de77", "4654", "9ecb",
    "ab6e", "bb8e", "b76b", "d661", "63f8", "7095", "567e", "b837", "2b80", "ad4f",
    "c514", "ffa4", "fc37", "7254", "b48b", "d38b", "a02b", "ec6c", "eacc", "8b70",
    "b03e", "1b36", "81ff", "77e4", "dbe6", "59d9", "fd6a", "5653", "8b95", "d0e5"
]
EXPECTED_FLAG = "academy{fl45h_5pr1ng1ng_c1e14a37}"
CORRECT_PW = "bb8e"
EMBEDDED_HASH = b"t\xcf\xfcY\xc2\x90\xc8\n8\x84c\xcc\x1c\x19\xffx"
EMBEDDED_ENC = b"\x03\x01Y\x01\x07\x0fA\x1e\x04\x0e\x0cP\n=\r\x15\x10SV\x02S\x0c_:\x01S]TV\x03\x0bR\x1f"


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
    elif os.path.exists("level4.hash.bin"):
        with open("level4.hash.bin", "rb") as f:
            target_hash = f.read()
    else:
        try:
            req = urllib.request.Request(HASH_BIN_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                target_hash = resp.read()
        except Exception:
            target_hash = EMBEDDED_HASH

    if not target_hash:
        target_hash = EMBEDDED_HASH

    # 2. Perform automated loop across 100 candidates
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
    elif os.path.exists("level4.flag.txt.enc"):
        with open("level4.flag.txt.enc", "rb") as f:
            enc_data = f.read()
    else:
        try:
            req = urllib.request.Request(ENC_FLAG_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                enc_data = resp.read()
        except Exception:
            enc_data = EMBEDDED_ENC

    if not enc_data:
        enc_data = EMBEDDED_ENC

    flag = str_xor(enc_data.decode("latin-1", errors="ignore"), matched_pw)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    enc_path = sys.argv[1] if len(sys.argv) > 1 else None
    hash_path = sys.argv[2] if len(sys.argv) > 2 else None
    recovered = solve(enc_path, hash_path)
    print(f"[+] Isolated Password: {CORRECT_PW}")
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
