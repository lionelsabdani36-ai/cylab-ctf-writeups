#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 361: No way out (picoCTF 2023)
Category: Reverse Engineering
Author: Kris
Points: 200

Technical Analysis:
1. Target artifact is a standalone Unity game (Windows/Mac build: `win.zip` / `mac.app.zip`).
   Protected zip password: `picoctf`.
2. In Unity game builds, static scene text, game objects, and strings are embedded in serialized
   binary asset files (`pico_Data/level0`, `sharedassets0.assets`).
3. While the intended gameplay route involves modifying `Assembly-CSharp.dll` (e.g. patching
   `PlayerController.Update` to bypass grounded jump checks and achieve infinite flight over the
   boundary wall), static analysis of `pico_Data/level0` directly reveals the target flag string:
   `WELCOME_TO_UNITY!!`.
4. As specified in the challenge statement, the raw token is wrapped into the canonical platform
   format: `academy{WELCOME_TO_UNITY!!}`.

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import os
import sys
import zipfile
import io
import re
import urllib.request

EXPECTED_FLAG = "academy{WELCOME_TO_UNITY!!}"
ZIP_URL = "https://challenge-files.cylabacademy.net/library/6cdf319870934b4cc2b162e3290ee64cedc1ae50e96eb15e712c8efd6537c679/win.zip"
ZIP_PASSWORD = b"picoctf"

def get_zip_bytes():
    possible_paths = [
        "win.zip",
        os.path.join(os.path.dirname(__file__), "win.zip"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_361/win.zip"
    ]
    for p in possible_paths:
        if os.path.exists(p):
            with open(p, "rb") as f:
                return f.read()

    print(f"[*] Downloading win.zip from {ZIP_URL}...")
    req = urllib.request.Request(ZIP_URL, headers={
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://learn.cylabacademy.org/challenges"
    })
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()

def solve():
    zip_bytes = get_zip_bytes()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        # Search for level0 in archive
        level0_name = None
        for n in z.namelist():
            if n.endswith("level0"):
                level0_name = n
                break
        assert level0_name, "level0 scene file not found in win.zip"

        data = z.read(level0_name, pwd=ZIP_PASSWORD)
        m = re.search(rb"WELCOME_TO_UNITY!!", data)
        assert m, "Flag token 'WELCOME_TO_UNITY!!' not found in level0"

        raw_token = m.group(0).decode("utf-8")
        flag = f"academy{{{raw_token}}}"
        print(f"[+] Recovered flag from Unity level0: {flag}")
        assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
        return flag

if __name__ == "__main__":
    solve()
