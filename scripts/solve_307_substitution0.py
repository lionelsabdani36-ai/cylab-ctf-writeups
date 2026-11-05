#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 307: substitution0 (picoCTF 2022)
Category: Cryptography / Monoalphabetic Substitution Cipher Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Cryptographic Assessment Techniques)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

Description:
A message has come in but it seems to be all scrambled. Luckily it seems to
have the key at the beginning. Can you crack this substitution cipher?
Download the message here.
Hint: Try a frequency attack. An online tool might help.

Methodology:
- The challenge provides a message encrypted with a monoalphabetic substitution cipher.
- The first line of the file explicitly defines the 26-character substitution key alphabet:
  "DJHMILABFORYVGNKUXQSCPEWZT"
- Each character in this key alphabet maps 1-to-1 to the standard English alphabet:
  'D' -> 'A', 'J' -> 'B', 'H' -> 'C', 'M' -> 'D', ..., 'T' -> 'Z'
- The cipher text is a segment of Edgar Allan Poe's "The Gold-Bug".
- The final line presents the encrypted flag:
  "Sbi lyda fq: dhdmivz{5CJ5717C710G_3P0YC710G_6D8H4822}"
- Substituting cipher letters back to plaintext letters yields:
  "The flag is: academy{5UB5717U710N_3V0LU710N_6A8C4822}"

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/c81cd186dacb4ad82560df3b81fe365fc1c38a1c7dca9a73a9604c5345ab4473/message.txt"
EXPECTED_FLAG = "academy{5UB5717U710N_3V0LU710N_6A8C4822}"
STANDARD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def decrypt_substitution(text: str, key: str) -> str:
    key_upper = key.strip().upper()
    c2p = {}
    for i, c in enumerate(key_upper):
        c2p[c] = STANDARD_ALPHA[i]
        c2p[c.lower()] = STANDARD_ALPHA[i].lower()

    return "".join(c2p.get(ch, ch) for ch in text)


def solve(file_path: str | None = None) -> str:
    content = ""
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif os.path.exists("message.txt"):
        with open("message.txt", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

    lines = content.strip().split("\n")
    if not lines:
        raise ValueError("Empty message content")

    key_line = lines[0].strip()
    cipher_body = "\n".join(lines[1:])

    plaintext = decrypt_substitution(cipher_body, key_line)

    m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", plaintext)
    if not m:
        raise ValueError("Flag pattern not found in decrypted plaintext")

    flag = m.group(0)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
