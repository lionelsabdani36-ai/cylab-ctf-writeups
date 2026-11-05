#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 239: convertme.py (Beginner picoMini 2022)
Category: General Skills / Radix Transformation & Static Flag Recovery
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Number Base Analysis & Static Cryptographic Logic Recovery)

Description:
Run the Python script and convert the given number from decimal to binary to get the flag.
- Script: https://challenge-files.cylabacademy.net/library/d507213597114cdf0943d7f7c585eab624e16586a7cdcb88229fd24c143128a1/convertme.py

Vulnerability Analysis & Core Concept:
- Radix Transformation (Decimal to Binary):
  Converting a base-10 integer to base-2 binary representation involves successive division by 2
  or using Python's built-in `bin(n)[2:]`.
- Static Cryptographic Extraction:
  The script protects the flag by conditioning its decryption on user input:
    `if ans_num == num:`
        `flag = str_xor(flag_enc, 'enkidu')`
  However, both the ciphertext `flag_enc` (a sequence of 32 `chr()` literals) and the static XOR key `'enkidu'`
  are bundled directly in the script. The flag can be completely recovered without running the interactive prompt.

Recovered Flag: academy{4ll_y0ur_b4535_fff0af3d}
Verified: POST /api/submissions/ -> correct: true
"""

import sys
import os
import urllib.request

SCRIPT_URL = "https://challenge-files.cylabacademy.net/library/d507213597114cdf0943d7f7c585eab624e16586a7cdcb88229fd24c143128a1/convertme.py"
HARDCODED_KEY = "enkidu"
FLAG_ENC_CHARS = (
    chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) +
    chr(0x1c) + chr(0x15) + chr(0x5f) + chr(0x05) + chr(0x08) + chr(0x2a) +
    chr(0x1c) + chr(0x5e) + chr(0x1e) + chr(0x1b) + chr(0x3b) + chr(0x17) +
    chr(0x51) + chr(0x5b) + chr(0x58) + chr(0x5c) + chr(0x3b) + chr(0x13) +
    chr(0x03) + chr(0x08) + chr(0x5b) + chr(0x08) + chr(0x02) + chr(0x46) +
    chr(0x01) + chr(0x13)
)
EXPECTED_FLAG = "academy{4ll_y0ur_b4535_fff0af3d}"


def str_xor(secret: str, key: str) -> str:
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])


def convert_dec_to_bin(dec_val: int) -> str:
    return bin(dec_val)[2:]


def solve(target_script: str | None = None) -> str:
    # Method 1: Static decryption using bundled ciphertext and key
    recovered = str_xor(FLAG_ENC_CHARS, HARDCODED_KEY)
    assert recovered == EXPECTED_FLAG, f"Flag mismatch: {recovered} vs {EXPECTED_FLAG}"
    return recovered


if __name__ == "__main__":
    script_arg = sys.argv[1] if len(sys.argv) > 1 else None
    recovered = solve(script_arg)
    print(f"[+] Decimal to Binary conversion example: 42 -> {convert_dec_to_bin(42)}")
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
