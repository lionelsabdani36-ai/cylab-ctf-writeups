#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: WinAntiDbg0x200 (ID: 430)
Category: Reverse Engineering / Windows Anti-Debugging & PE Binary Analysis
Event: picoCTF 2024
Difficulty: Medium (300 pts)

Analysis & Recovery:
1. Challenge provides a Windows PE32 executable (WinAntiDbg0x200.exe) and config.bin.
2. The binary executes advanced multi-process anti-debugging verification:
   - Level 2 anti-debugging checks:
     a) Main process executes an initial 3-round cyclic popcount shift on buffer s1 (function 0x401090 with count = 3).
     b) Spawns a child process passing the parent PID as an argument (CreateProcessW with "%s %d").
     c) Inside function 0x4011d0, before process synchronization, it executes a 5-round shift (count = 5).
     d) The child process calls DebugActiveProcess(parent_pid).
        - If an external debugger is already attached to the parent, DebugActiveProcess fails and child exits with 0xbeef.
        - If no debugger is attached, DebugActiveProcess succeeds and child exits with 0.
     e) In the parent process, after WaitForSingleObject and CloseHandle, two 4-round shifts are executed (count = 4 + 4 = 8).
     f) The parent checks child exit code and IsDebuggerPresent(): if clean, it executes the final 1-round shift (count = 1).
3. Total shift iterations across the legitimate execution path:
   Total iterations = 3 + 5 + 4 + 4 + 1 = 17 rounds.
4. Each round shifts each character in s1 according to the Hamming weight (popcount) of its index modulo 255:
   s1[i] = 'a' + ((s1[i] - 'a' + popcount(i % 255)) % 26)
5. Finally, function 0x401180 performs a bitwise XOR of the 17-round shifted keystream with ciphertext buffer s2:
   flag[i] = s1[i] ^ s2[i]
6. Output flag:
   academy{0x200_debug_f0r_Win_cf686cdb}
"""

import os
import sys
import zipfile
import urllib.request
import re

ZIP_URL = "https://challenge-files.cylabacademy.net/library/842fd067da1fb3a42394847ad47fa3f7a479a37a676e8053f175959077b9930e/WinAntiDbg0x200.zip"
ZIP_PASSWORD = b"academy"

def solve(config_path: str = "") -> str:
    if not config_path or not os.path.exists(config_path):
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_430")
        os.makedirs(work_dir, exist_ok=True)
        config_path = os.path.join(work_dir, "config.bin")
        if not os.path.exists(config_path):
            zip_path = os.path.join(work_dir, "WinAntiDbg0x200.zip")
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

    # 3 (main pre-spawn) + 5 (spawn setup) + 4 (post-wait) + 4 (post-close) + 1 (post-check) = 17
    total_iterations = 3 + 5 + 4 + 4 + 1
    print(f"[*] Simulating multi-process execution path ({total_iterations} rounds)...")
    apply_shift(s1, total_iterations)

    print("[*] XORing transformed keystream with ciphertext buffer...")
    flag_bytes = bytes(a ^ b for a, b in zip(s1, s2))
    decoded = flag_bytes.decode("latin-1", "replace")
    print(f"[*] Decoded raw string: {decoded}")

    m = re.search(r"(?:academy|picoCTF|CTF)\{[^}]+\}", decoded)
    if not m:
        raise RuntimeError(f"Flag not found in decoded bytes: {decoded}")

    flag = m.group(0)
    return flag

if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else ""
    recovered = solve(cfg)
    print(f"Recovered Flag: {recovered}")
