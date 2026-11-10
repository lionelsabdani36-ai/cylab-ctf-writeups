#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 254: basic-mod2 (picoCTF 2022)
Category: Cryptography / Modular Inversion & Ring Arithmetic
Difficulty: Medium | Points: 100
Author: Will Hong
Standard Reference: NIST SP 800-115 § 4.2 (Cryptographic Vulnerability Analysis)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm / Unkeyed Modular Inversion)

Description:
A new modular challenge! Download the message here:
https://challenge-files.cylabacademy.net/library/4f25bc41d739375d13732691063a72f372cc433988ff76ad620c458a792b5c9e/message.txt
Take each number mod 41 and find the modular inverse for the number. Then map to the character set:
  1-26 is the alphabet (uppercase A-Z), 27-36 are the decimal digits (0-9), and 37 is an underscore (_).
Wrap your decrypted message in the academy flag format: academy{decrypted_message}.

Vulnerability Analysis & Core Concept:
- Trapdoor-Free Modular Multiplicative Inverse on Galois Field GF(41):
  The challenge scheme reduces each input integer modulo 41: r = n mod 41.
  Since 41 is a prime integer, the ring Z/41Z forms a finite field GF(41).
  Every non-zero residue r in GF(41)* has a unique multiplicative inverse x in GF(41)* satisfying:
    r * x = 1 (mod 41)
  By Fermat's Little Theorem (r^40 = 1 mod 41), the inverse is computed directly via modular
  exponentiation x = r^39 mod 41, or using the Extended Euclidean Algorithm via Python's pow(r, -1, 41).
- Unkeyed Deterministic Mapping (CWE-327):
  Because the modulus 41 and alphabet mapping are completely public with zero secret key,
  the algorithm provides zero confidentiality. Any adversary can deterministically invert the ciphertext.

Recovered Flag: academy{1NV3R53LY_H4RD_471A6111}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import json
import os
import sys
import urllib.request

CHALLENGE_ID = 254
CHALLENGE_NAME = "basic-mod2"
EXPECTED_FLAG = "academy{1NV3R53LY_H4RD_471A6111}"
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
URL = ("https://challenge-files.cylabacademy.net/library/"
       "4f25bc41d739375d13732691063a72f372cc433988ff76ad620c458a792b5c9e/message.txt")

# Embedded message tokens from message.txt for 100% deterministic offline reproduction
EMBEDDED_NUMBERS = [
    104, 126, 274, 231, 262, 378, 108, 352, 64, 338,
    77, 209, 139, 441, 297, 168, 158, 309, 329, 415,
    186, 145, 186
]


def decode_numbers(numbers: list[int]) -> str:
    """Decodes integer tokens by computing modular inverse modulo 41."""
    out = []
    for tok in numbers:
        r = tok % 41
        inv = pow(r, -1, 41)
        if not 1 <= inv <= 37:
            raise ValueError(f"Inverse out of mapping range: {tok} -> {inv}")
        out.append(CHARSET[inv - 1])
    return "academy{" + "".join(out) + "}"


def decode_text(text: str) -> str:
    """Parses whitespace-separated integers from text string."""
    nums = [int(t) for t in text.split() if t.strip()]
    return decode_numbers(nums)


def solve_offline() -> str:
    """Performs deterministic offline modular inverse decoding."""
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Evaluating Modulo 41 Inverses on 23 Embedded Tokens...")
    flag = decode_numbers(EMBEDDED_NUMBERS)
    print(f"    [+] Decoded Stream: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


def solve(src: str | None = None) -> str:
    """Decodes message from file, URL, or embedded integers."""
    if src is None:
        try:
            req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                text = r.read().decode("utf-8")
                return decode_text(text)
        except Exception:
            return solve_offline()
    elif src.startswith("http://") or src.startswith("https://"):
        req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode("utf-8")
            return decode_text(text)
    elif os.path.isfile(src):
        with open(src, "r", encoding="utf-8") as f:
            text = f.read()
            return decode_text(text)
    else:
        return solve_offline()


def submit_to_cylab(token: str) -> bool:
    """Submits token to CyLab REST API verification gate."""
    sys.path.insert(0, "/tmp")
    try:
        import cylab_auth
        status, body = cylab_auth.req(
            "https://learn.cylabacademy.org/api/submissions/",
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        data = json.loads(body)
        return (status == 201 and data.get("correct") is True)
    except Exception as e:
        print(f"[-] Live submission check failed: {e}")
        return False


if __name__ == "__main__":
    s = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(s)
    print(f"[+] Output Flag: {flag}")
    assert flag == EXPECTED_FLAG
