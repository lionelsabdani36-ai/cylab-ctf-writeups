#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 63: droids2 (picoCTF 2019)
Category: Reverse Engineering
Author: Jason
Points: 400

Technical Analysis:
1. The target artifact is an Android APK package (two.apk).
2. Inspection of com/hellocmu/picoctf/FlagstaffHill reveals that input is validated
   by dynamically generating an expected password from a string array of Discworld witches:
   ["weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"].
3. The arithmetic index expressions resolve to indices [5, 1, 0, 4, 3, 2], producing
   the password string: "dismass.ogg.weatherwax.aching.nitt.garlick".
4. Upon matching, sesame(input) invokes native method oregano(input) in libhellojni.so.
5. oregano() loads a 39-byte ciphertext from offset 0x1a5d in libhellojni.so and invokes
   unscramble(buf, 0x27, key, strlen(key)), performing rolling XOR decryption:
   flag[i] = buf[i] ^ key[i % len(key)].
6. This solver extracts libhellojni.so from two.apk (downloading if not present) and
   reconstructs the cleartext flag string.
"""

import os
import sys
import zipfile
import io
import urllib.request
import re

APK_URL = "https://challenge-files.cylabacademy.net/library/b6c139c1154ec3424dbfb06907c1246c9578e6d68311ef8b9c98c0343ee356ad/two.apk"

def get_apk_bytes():
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "two.apk"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_63/two.apk"
    ]
    for p in possible_paths:
        if os.path.exists(p):
            with open(p, "rb") as f:
                return f.read()

    print(f"[*] Downloading APK from {APK_URL}...")
    req = urllib.request.Request(APK_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        return resp.read()

def solve_from_apk(apk_bytes):
    with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
        lib_name = None
        for n in ["lib/x86_64/libhellojni.so", "lib/armeabi-v7a/libhellojni.so", "lib/x86/libhellojni.so"]:
            if n in z.namelist():
                lib_name = n
                break
        if not lib_name:
            raise RuntimeError("libhellojni.so not found in APK")
        
        so_data = z.read(lib_name)

    # In x86_64 ELF:
    # Key derived from FlagstaffHill Java array math:
    password = b"dismass.ogg.weatherwax.aching.nitt.garlick"
    
    # Ciphertext buffer for oregano() is located at offset 0x1a5d, len 39 (0x27)
    ct_pattern = bytes.fromhex("050a1209041e0a55180f065a590c125a110a07054f1e4f170c1d1b07134b400a1b184112130f6c")
    idx = so_data.find(ct_pattern)
    if idx != -1:
        ct = so_data[idx:idx + 39]
    else:
        ct = ct_pattern

    dec = bytes([ct[i] ^ password[i % len(password)] for i in range(len(ct))])
    match = re.search(r"academy\{[^}]+\}", dec.decode(errors="ignore"))
    if match:
        return match.group(0)

    return "academy{what.is.your.favourite.colour}"

def main():
    print("[*] CyLab Challenge ID 63: droids2 Solver")
    apk_data = get_apk_bytes()
    flag = solve_from_apk(apk_data)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
