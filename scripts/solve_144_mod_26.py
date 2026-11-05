#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 144: Mod 26 (picoCTF 2021)
Category: Cryptography / Caesar Cipher & ROT13 Reversal
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Review of Cryptographic Controls & Algorithm Strength)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

Description:
Cryptography can be easy, do you know what ROT13 is?
Target asset: values.txt
Asset URL: https://challenge-files.cylabacademy.net/library/f3d35996f9541b57c61263b98a9520596dbb45867d87d5f079d883b76348c5d8/values.txt

Vulnerability & Methodology:
- Monoalphabetic substitution cipher with fixed rotation key (k = 13 mod 26).
- ROT13 is an involution (its own inverse), rendering encryption and decryption identical.
- Ciphertext: npnqrzl{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_5p5s5o36}
- Decoded flag: academy{next_time_I'll_try_2_rounds_of_rot13_5c5f5b36}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import sys
import codecs
import re
import urllib.request

ASSET_URL_VALUES = "https://challenge-files.cylabacademy.net/library/f3d35996f9541b57c61263b98a9520596dbb45867d87d5f079d883b76348c5d8/values.txt"
EXPECTED_FLAG = "academy{next_time_I'll_try_2_rounds_of_rot13_5c5f5b36}"


def solve(file_path: str | None = None) -> str:
    raw_text = None
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = f.read().strip()
    elif os.path.exists("values.txt"):
        with open("values.txt", "r", encoding="utf-8", errors="ignore") as f:
            raw_text = f.read().strip()
    elif os.path.exists("/tmp/solve_144/values.txt"):
        with open("/tmp/solve_144/values.txt", "r", encoding="utf-8", errors="ignore") as f:
            raw_text = f.read().strip()
    else:
        try:
            req = urllib.request.Request(ASSET_URL_VALUES, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_text = resp.read().decode("utf-8", errors="ignore").strip()
        except Exception as e:
            raise RuntimeError(f"Failed to fetch values.txt asset: {e}")

    # Method: Apply ROT13 decoding
    decoded = codecs.decode(raw_text, "rot_13")
    m = re.search(r"academy\{[^}]+\}", decoded)
    if m:
        flag = m.group(0)
        assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
        return flag

    raise ValueError("Flag pattern not found after ROT13 decoding")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(path)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
