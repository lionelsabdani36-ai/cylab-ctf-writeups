#!/usr/bin/env python3
"""Solver for Challenge 351 - HideToSee (picoCTF 2023, Cryptography).

The challenge provides a JPEG image ('atbash.jpg').
Analysis reveals:
1. Steghide steganography is applied to the image with an empty passphrase.
2. Extracting embedded data yields an encoded ciphertext:
   `zxzwvnb{zgyzhs_xizxp_6167yw8v}`
3. The image filename hints at the Atbash substitution cipher (a <-> z, b <-> y, ..., m <-> n).
4. Applying the Atbash substitution decrypts the token:
   zxzwvnb -> academy
   zgyzhs  -> atbash
   xizxp   -> crack
   6167yw8v -> 6167bd8e
   Yielding the flag: academy{atbash_crack_6167bd8e}

Verified: academy{atbash_crack_6167bd8e} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import os
import subprocess
import sys
import tempfile
import urllib.request

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/4430e164c62a6474394efb666c3b2c24511a0823a3408e5e7a19a37940f0e592/atbash.jpg"
EXPECTED_FLAG = "academy{atbash_crack_6167bd8e}"


def atbash_decrypt(text: str) -> str:
    res = []
    for c in text:
        if "a" <= c <= "z":
            res.append(chr(ord("z") - (ord(c) - ord("a"))))
        elif "A" <= c <= "Z":
            res.append(chr(ord("Z") - (ord(c) - ord("A"))))
        else:
            res.append(c)
    return "".join(res)


def solve(image_path: str = "atbash.jpg") -> str:
    if not os.path.exists(image_path):
        print(f"[*] Downloading {IMAGE_URL}...")
        urllib.request.urlretrieve(IMAGE_URL, image_path)

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp_name = tmp.name

    try:
        proc = subprocess.run(
            ["steghide", "extract", "-sf", image_path, "-p", "", "-xf", tmp_name, "-f"],
            capture_output=True,
            text=True,
            check=True,
        )
        with open(tmp_name, "r", encoding="utf-8", errors="replace") as f:
            raw_extracted = f.read().strip()
        print(f"[+] Extracted ciphertext from steghide: {raw_extracted}")
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)

    flag = atbash_decrypt(raw_extracted)
    print(f"[+] Decrypted flag via Atbash cipher: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/atbash.jpg" if os.path.exists("/tmp/atbash.jpg") else "atbash.jpg"
    solve(target)
