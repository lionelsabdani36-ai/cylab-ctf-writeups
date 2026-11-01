#!/usr/bin/env python3
"""Solver for Challenge 381 - timer (picoCTF 2023, Reverse Engineering).

The challenge provides an Android Application Package ('timer.apk').
Analysis reveals:
1. Android APK packages are standard ZIP archives containing compiled DEX bytecode (classes.dex,
   classes2.dex, classes3.dex), XML manifests, and embedded resources.
2. In classes3.dex, static analysis of the compiled Dalvik bytecode reveals hardcoded string constants
   associated with the timer application.
3. Carving string literals matching the platform flag regex pattern directly yields:
   academy{t1m3r_r3v3rs3d_succ355fully_17496}

Verified: academy{t1m3r_r3v3rs3d_succ355fully_17496} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import io
import os
import re
import sys
import urllib.request
import zipfile

APK_URL = "https://challenge-files.cylabacademy.net/library/b31248aec6287cbe220d0dbfa55e216b87e6175b3561d441062bfdd018f3cacc/timer.apk"
EXPECTED_FLAG = "academy{t1m3r_r3v3rs3d_succ355fully_17496}"


def solve(apk_path: str = "timer.apk") -> str:
    if not os.path.exists(apk_path):
        print(f"[*] Downloading {APK_URL}...")
        urllib.request.urlretrieve(APK_URL, apk_path)

    with open(apk_path, "rb") as f:
        data = f.read()

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                content = z.read(name)
                match = re.search(rb"(?:academy|picoCTF|CTF)\{[^}]+\}", content)
                if match:
                    flag = match.group(0).decode("utf-8")
                    print(f"[+] Recovered flag from {name}: {flag}")
                    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
                    return flag

    raise ValueError("Flag not found in APK DEX files")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/timer.apk" if os.path.exists("/tmp/timer.apk") else "timer.apk"
    solve(target)
