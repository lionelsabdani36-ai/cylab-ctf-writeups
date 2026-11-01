#!/usr/bin/env python3
"""Solver for Challenge 420 - Mob psycho (picoCTF 2024, Forensics).

The challenge provides an Android application package ('mobpsycho.apk').
Forensic analysis reveals:
1. Android APK packages adhere to standard ZIP archive specifications.
2. Inspecting the archive table reveals an unusual plain text resource:
   `res/color/flag.txt`
3. Extracting `res/color/flag.txt` yields a 74-character hexadecimal string:
   '61636164656d797b6178386d433052553676655f4e5838356c346178386d436c5f30353465336363347d'
4. Decoding the hex bytes restores the official flag:
   academy{ax8mC0RU6ve_NX85l4ax8mCl_054e3cc4}

Verified: academy{ax8mC0RU6ve_NX85l4ax8mCl_054e3cc4} (POST /api/submissions/ -> correct:true)
"""
import io
import os
import sys
import urllib.request
import zipfile

APK_URL = "https://challenge-files.cylabacademy.net/library/03425ca32581a113283d4b3270dc798c848e4b4512c28e30c88887c3183b9967/mobpsycho.apk"
EXPECTED_FLAG = "academy{ax8mC0RU6ve_NX85l4ax8mCl_054e3cc4}"


def solve(apk_path: str = "mobpsycho.apk") -> str:
    if not os.path.exists(apk_path):
        print(f"[*] Downloading {APK_URL}...")
        urllib.request.urlretrieve(APK_URL, apk_path)

    print(f"[*] Inspecting APK archive: {apk_path}...")
    with zipfile.ZipFile(apk_path, "r") as zf:
        namelist = zf.namelist()
        flag_entry = next((name for name in namelist if name.endswith("flag.txt")), None)
        if not flag_entry:
            raise FileNotFoundError("flag.txt entry not found within APK archive")

        print(f"[+] Located flag resource at: {flag_entry}")
        raw_hex = zf.read(flag_entry).decode("utf-8").strip()

    flag = bytes.fromhex(raw_hex).decode("utf-8")
    print(f"[+] Recovered flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "/tmp/mobpsycho.apk" if os.path.exists("/tmp/mobpsycho.apk") else "mobpsycho.apk")
