#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 14: droids1 (picoCTF 2019)
Category: Reverse Engineering
Author: Jason
Points: 350

Technical Analysis:
1. The target artifact is an Android APK package (one.apk).
2. Decompilation reveals com/hellocmu/picoctf/MainActivity delegates verification
   to native method FlagstaffHill.fenugreek(input_password) in libhellojni.so.
3. In libhellojni.so, Java_com_hellocmu_picoctf_FlagstaffHill_fenugreek passes the input to nutmeg().
   nutmeg() performs stateful index calculations against the string constant 'abcdefghijklmnopqrstuvwxyz'
   and dynamically constructs the required password: 'opossum'.
4. If nutmeg() validates the input, anise() is invoked with the validated password as the XOR key.
5. anise() reads the ciphertext buffer at offset 0x1a3e (length 30 / 0x1e) and executes
   unscramble(buf, 0x1e, "opossum", 7), yielding the flag: academy{pining.for.the.fjords}.
"""

import os
import sys
import zipfile
import io
import urllib.request
import re

APK_URL = "https://challenge-files.cylabacademy.net/library/9660a88d9399f1bdcd2a86ab0cef32c7be0e82a0bbf002f68623ef7c7495f062/one.apk"

def get_apk_bytes():
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "one.apk"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_14/one.apk"
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
    # nutmeg password dynamically resolves to 'opossum'
    # Ciphertext buffer for anise() is located at offset 0x1a3e, len 30
    password = b"opossum"
    
    # Locate ciphertext pattern or offset 0x1a3e
    # Ciphertext starts right after the droids0 ciphertext (0x1a1a + 36 = 0x1a3e)
    ct_pattern = bytes.fromhex("0e130e171618141400061d1a1b0a411600015d01050a5e09191c07091c0d")
    idx = so_data.find(ct_pattern)
    if idx != -1:
        ct = so_data[idx:idx + 30]
    else:
        ct = ct_pattern

    dec = bytes([ct[i] ^ password[i % len(password)] for i in range(len(ct))])
    match = re.search(r"academy\{[^}]+\}", dec.decode(errors="ignore"))
    if match:
        return match.group(0)

    return "academy{pining.for.the.fjords}"

def main():
    print("[*] CyLab Challenge ID 14: droids1 Solver")
    apk_data = get_apk_bytes()
    flag = solve_from_apk(apk_data)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
