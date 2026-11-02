#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: WinAntiDbg0x100 (ID: 429)
Category: Reverse Engineering / Windows Anti-Debugging & PE Binary Analysis
Event: picoCTF 2024
Difficulty: Medium (200 pts)

Analysis & Recovery:
1. The Windows PE executable (WinAntiDbg0x100.exe) reads configuration and key material
   from config.bin:
   - Offset 0x00: Length of key buffers (0x29 = 41 bytes).
   - Offset 0x04: Buffer s1 (41 lowercase letters).
   - Offset 0x2e: Buffer s2 (41 raw bytes).
2. The binary executes an anti-debugging verification:
   - It performs an initial Caesar-like cyclic shift on buffer s1 with count = 7 (function 0x401440).
     The shift per index i is given by popcount(i % 255):
       s1[i] = 'a' + ((s1[i] - 'a' + popcount(i % 255)) % 26)
   - It calls IsDebuggerPresent() (kernel32.dll).
   - If a debugger is detected (eax != 0), it aborts after outputting an alert message.
   - If bypassed / not detected (eax == 0), it continues to execute a secondary shift on buffer s1
     with count = 11 (0xb), for a total shift count of 18 (7 + 11).
   - Finally, function 0x401530 XORs the transformed s1 buffer with s2:
       flag[i] = s1[i] ^ s2[i]
3. Reconstructing this algorithmic flow directly recovers the flag:
   academy{d3bug_f0r_th3_Win_0x100_411bc019}
"""

import os
import sys
import zipfile
import urllib.request
import re

ZIP_URL = "https://challenge-files.cylabacademy.net/library/a511bc7c37bbb4e8d1f755d2f668aaddbb7e474b2932e7816e34e935a0671ec9/WinAntiDbg0x100.zip"
ZIP_PASSWORD = b"academy"

def solve(config_path: str = "") -> str:
    if not config_path or not os.path.exists(config_path):
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_429")
        os.makedirs(work_dir, exist_ok=True)
        config_path = os.path.join(work_dir, "config.bin")
        if not os.path.exists(config_path):
            zip_path = os.path.join(work_dir, "WinAntiDbg0x100.zip")
            if not os.path.exists(zip_path):
                print(f"[*] Downloading {ZIP_URL}...")
                urllib.request.urlretrieve(ZIP_URL, zip_path)
            print("[*] Extracting archive...")
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(work_dir, pwd=ZIP_PASSWORD)

    print(f"[*] Parsing {config_path}...")
    with open(config_path, "rb") as f:
        data = f.read()

    length = int.from_bytes(data[:4], "little")
    print(f"[*] Buffer length: {length}")
    s1 = bytearray(data[4 : 4 + length])
    s2 = bytearray(data[4 + length + 1 : 4 + length + 1 + length])

    def apply_shift(buf: bytearray, iterations: int):
        for _ in range(iterations):
            for i in range(len(buf)):
                shift_val = bin(i % 255).count("1")
                buf[i] = ord("a") + ((buf[i] - ord("a") + shift_val) % 26)

    print("[*] Simulating execution path (Shift 7 + Shift 11)...")
    apply_shift(s1, 7 + 11)

    print("[*] XORing transformed keystream with ciphertext buffer...")
    flag_bytes = bytes(a ^ b for a, b in zip(s1, s2))
    decoded = flag_bytes.decode("latin-1", "replace")
    print(f"[*] Decoded: {decoded}")

    m = re.search(r"(?:academy|picoCTF|CTF)\{[^}]+\}", decoded)
    if not m:
        raise RuntimeError(f"Flag not found in decoded bytes: {decoded}")

    flag = m.group(0)
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"Recovered Flag: {flag}")
