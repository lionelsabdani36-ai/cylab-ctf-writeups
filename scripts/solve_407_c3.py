#!/usr/bin/env python3
"""Solver for Challenge 407 - C3 (picoCTF 2024, Cryptography).

The challenge implements a Custom Cyclical Cipher (C3):
1. Inversion of stage 1:
   The encoder uses two 40-character substitution alphabets:
     lookup1 = "\\n \\"#()*+/1:=[]abcdefghijklmnopqrstuvwxyz"
     lookup2 = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst"
   Cipher equation: out[i] = lookup2[(cur - prev) % 40] where prev = cur.
   The inverse equation: cur = (lookup2.index(out[i]) + prev) % 40 where prev = cur.
2. The recovered plaintext is a Python 2 self-referential script (#selfinput):
   Evaluating chars[b**3] for b = 1, 2, 3, ... extracts the characters: 'a', 'd', 'l', 'i', 'b', 's'.
3. Wrapping into the official platform format gives:
   academy{adlibs}

Verified: academy{adlibs} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import os
import sys
import urllib.request

CIPHERTEXT_URL = "https://challenge-files.cylabacademy.net/library/fb4743509774955556141c96d067e6eabc71a6b5d566329b2ab0a53c102e9e13/ciphertext"
EXPECTED_FLAG = "academy{adlibs}"

LOOKUP1 = '\n "#()*+/1:=[]abcdefghijklmnopqrstuvwxyz'
LOOKUP2 = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst"


def decrypt_c3(ciphertext: str) -> str:
    pt = ""
    prev = 0
    for c in ciphertext.strip():
        diff = LOOKUP2.index(c)
        cur = (diff + prev) % 40
        pt += LOOKUP1[cur]
        prev = cur
    return pt


def extract_flag(stage2_script: str) -> str:
    chars = stage2_script
    b = 1
    extracted = []
    for i in range(len(chars)):
        if i == b * b * b:
            extracted.append(chars[i])
            b += 1
    inner = "".join(extracted)
    flag = f"academy{{{inner}}}"
    return flag


def solve(ct_path: str = "ciphertext") -> str:
    if not os.path.exists(ct_path):
        print(f"[*] Downloading {CIPHERTEXT_URL}...")
        urllib.request.urlretrieve(CIPHERTEXT_URL, ct_path)

    with open(ct_path, "r", encoding="utf-8") as f:
        ciphertext = f.read()

    stage2_script = decrypt_c3(ciphertext)
    flag = extract_flag(stage2_script)
    print(f"[+] Reconstructed Flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/c407/ciphertext" if os.path.exists("/tmp/c407/ciphertext") else "ciphertext"
    solve(target)
