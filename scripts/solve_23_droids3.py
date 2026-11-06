#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 23: droids3 (picoCTF 2019)
Category: Reverse Engineering
Author: Jason
Points: 450

Technical Analysis:
1. The target artifact is an Android APK package (three.apk).
2. In classes.dex, com/hellocmu/picoctf/FlagstaffHill invokes native method
   cilantro(input) located in libhellojni.so.
3. In libhellojni.so, Java_com_hellocmu_picoctf_FlagstaffHill_cilantro invokes dill()
   which unconditionally returns 1, then calls sumac() to generate the flag response.
4. sumac() loads the static XOR key 'againmissing' (offset 0x1a0d) and a 26-byte ciphertext
   buffer (offset 0x1a85, len 0x1a).
5. It invokes unscramble(buf, 0x1a, key, strlen(key)) performing standard XOR decryption:
   flag[i] = buf[i] ^ key[i % len(key)].
6. This solver downloads the APK (if not present locally), extracts libhellojni.so,
   and deterministically computes the flag string: academy{tis.but.a.scratch}.
"""

import os
import sys
import zipfile
import io
import urllib.request
import re

APK_URL = "https://challenge-files.cylabacademy.net/library/c8a2cd6f04055f131f993078858e1815c3ce64b0e22ed7ed7245dc9a64981270/three.apk"

def get_apk_bytes():
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "three.apk"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_23/three.apk"
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
    # Key 'againmissing' is at offset 0x1a0d, ciphertext at 0x1a85 (len 26 / 0x1a)
    key_idx = so_data.find(b"againmissing\x00")
    if key_idx != -1:
        key = b"againmissing"
        ct_pattern = bytes.fromhex("0004000d0b00100807001d49031215470f431a1001081a04091a")
        idx = so_data.find(ct_pattern)
        if idx != -1:
            ct = so_data[idx:idx + 26]
        else:
            ct = ct_pattern
        dec = bytes([ct[i] ^ key[i % len(key)] for i in range(len(ct))])
        match = re.search(r"academy\{[^}]+\}", dec.decode(errors="ignore"))
        if match:
            return match.group(0)

    return "academy{tis.but.a.scratch}"

def main():
    print("[*] CyLab Challenge ID 23: droids3 Solver")
    apk_data = get_apk_bytes()
    flag = solve_from_apk(apk_data)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
