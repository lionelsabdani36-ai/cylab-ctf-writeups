#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 373: rotation (picoCTF 2023)
Category: Cryptography / Caesar Cipher & Rotation Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Cryptographic Algorithm and Key Strength Analysis)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

Description:
You will find the flag after decrypting this file
Download the encrypted flag here.
Hint: Sometimes rotation is right

Methodology:
- The challenge provides an encrypted text file with a Caesar / rotation cipher.
- Encrypted ciphertext: "ikilmug{z0bib1wv_l3kzgxb3l_91mllij9}"
- Evaluating shift offsets (0-25) over the Latin alphabet modulo 26:
  Shift 8 (left shift of 8, or right shift of 18) aligns "ikilmug" to "academy":
  'i' (ord 105) - 8 = 'a' (ord 97)
  'k' (ord 107) - 8 = 'c' (ord 99)
- Decrypted result recovers the valid flag format:
  academy{r0tat1on_d3crypt3d_91eddab9}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/545f29dd6d01fbbfe2cb0c2616132c3b10c64c676d94c9cc88d3fc15020078a2/encrypted.txt"
EXPECTED_FLAG = "academy{r0tat1on_d3crypt3d_91eddab9}"


def decrypt_rot(text: str, shift: int) -> str:
    res = []
    for c in text:
        if "a" <= c <= "z":
            res.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            res.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
        else:
            res.append(c)
    return "".join(res)


def solve(file_path: str | None = None) -> str:
    content = ""
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
    elif os.path.exists("encrypted.txt"):
        with open("encrypted.txt", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore").strip()

    flag = ""
    for shift in range(26):
        cand = decrypt_rot(content, shift)
        m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", cand)
        if m:
            flag = m.group(0)
            break

    if not flag:
        raise ValueError("Failed to recover flag through rotational shift")

    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
