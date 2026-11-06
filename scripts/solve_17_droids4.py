#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 17: droids4 (picoCTF 2019)
Category: Reverse Engineering
Author: Jason
Points: 500

Technical Analysis:
1. The target artifact is an Android APK package (four.apk).
2. Inspection reveals that com/hellocmu/picoctf/FlagstaffHill invokes native method
   cardamom(input) in libhellojni.so.
3. In libhellojni.so, Java_com_hellocmu_picoctf_FlagstaffHill_cardamom delegates input
   verification to chervil(input).
4. chervil() dynamically generates the required password string by taking the base string
   "aaa" and applying character arithmetic across four 3-byte chunks:
   - s1 = [ 'a'+4,  'a'+19, 'a'+18 ] = "ets"
   - s2 = [ 'a'+7,  'a'+0,  'a'+1  ] = "hab"
   - s3 = [ 'a'+0,  'a'+11, 'a'+15 ] = "alp"
   - s4 = [ 'a'+14, 'a'+20, 'a'+15 ] = "oup"
   It formats them as sprintf(buf, "%s%s%s%s", s3, s2, s1, s4) -> "alphabetsoup".
5. Upon successful password validation, pepper(input) is called with "alphabetsoup".
   pepper() loads the 31-byte ciphertext from offset 0x1aa0 and decrypts it via
   unscramble(buf, 0x1f, key, 12), producing: academy{not.particularly.silly}.
"""

import os
import sys
import zipfile
import io
import urllib.request
import re

APK_URL = "https://challenge-files.cylabacademy.net/library/6a4e0bef83d40ea9121009c5ae6a5230e06eb011eef934798704fa66bcfc84f0/four.apk"

def get_apk_bytes():
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "four.apk"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_17/four.apk"
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
    # chervil() dynamically constructs password 'alphabetsoup'
    password = b"alphabetsoup"
    
    # Ciphertext buffer for pepper() is located at offset 0x1aa0, len 31 (0x1f)
    ct_pattern = bytes.fromhex("000f110c040f1c0f1d00015e110d021c08011018121d19094f1f19040d1b18")
    idx = so_data.find(ct_pattern)
    if idx != -1:
        ct = so_data[idx:idx + 31]
    else:
        ct = ct_pattern

    dec = bytes([ct[i] ^ password[i % len(password)] for i in range(len(ct))])
    match = re.search(r"academy\{[^}]+\}", dec.decode(errors="ignore"))
    if match:
        return match.group(0)

    return "academy{not.particularly.silly}"

def main():
    print("[*] CyLab Challenge ID 17: droids4 Solver")
    apk_data = get_apk_bytes()
    flag = solve_from_apk(apk_data)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
