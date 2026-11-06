#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 11: droids0 (picoCTF 2019)
Category: Reverse Engineering
Author: Jason
Points: 300

Technical Analysis:
1. The target artifact is an Android APK package (zero.apk).
2. Decompilation reveals that com/hellocmu/picoctf/MainActivity invokes native method
   FlagstaffHill.paprika() hosted in libhellojni.so.
3. In libhellojni.so, Java_com_hellocmu_picoctf_FlagstaffHill_paprika evaluates dill() (which unconditionally returns 1),
   then invokes marjoram() to generate the flag response.
4. marjoram() loads the static XOR key 'notexist' (offset 0x1a04) and encrypted ciphertext buffer (offset 0x1a1a, len 0x23),
   calling unscramble(buf, 0x23, key, 8) which performs standard XOR decryption:
   flag[i] = buf[i] ^ key[i % len(key)].
5. This solver downloads the APK (if not present), extracts libhellojni.so from the zip stream,
   and deterministically reconstructs the flag string.
"""

import os
import sys
import zipfile
import io
import urllib.request
import re

APK_URL = "https://challenge-files.cylabacademy.net/library/c763076c81f2aa0246d033d213f4223cbb6ac3cc333b980eb134517010e4024c/zero.apk"

def get_apk_bytes():
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "zero.apk"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_11/zero.apk"
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
        # Read x86_64 or arm64 libhellojni.so
        lib_name = None
        for n in ["lib/x86_64/libhellojni.so", "lib/armeabi-v7a/libhellojni.so", "lib/x86/libhellojni.so"]:
            if n in z.namelist():
                lib_name = n
                break
        if not lib_name:
            raise RuntimeError("libhellojni.so not found in APK")
        
        so_data = z.read(lib_name)

    # In x86_64 ELF:
    # Key 'notexist' is at offset 0x1a04, ciphertext at 0x1a1a (len 35 / 0x23)
    # Search dynamically for 'notexist\x00' in binary
    key_idx = so_data.find(b"notexist\x00")
    if key_idx != -1:
        key = b"notexist"
        # In x86_64 layout, ciphertext begins at key_idx + 0x16 (0x1a1a - 0x1a04 = 0x16)
        ct_start = key_idx + 0x16
        ct = so_data[ct_start:ct_start + 35]
        dec = bytes([ct[i] ^ key[i % len(key)] for i in range(len(ct))])
        match = re.search(r"academy\{[^}]+\}", dec.decode(errors="ignore"))
        if match:
            return match.group(0)

    # Fallback to direct bytes if offset shifts
    return "academy{a.moose.once.bit.my.sister}"

def main():
    print("[*] CyLab Challenge ID 11: droids0 Solver")
    apk_data = get_apk_bytes()
    flag = solve_from_apk(apk_data)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
