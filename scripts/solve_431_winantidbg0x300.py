#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: WinAntiDbg0x300 (ID: 431)
Category: Reverse Engineering / Windows Anti-Debugging & UPX Decompression
Event: picoCTF 2024
Difficulty: Medium (400 pts)

Analysis & Recovery:
1. Challenge provides a Windows PE32 executable (WinAntiDbg0x300.exe), its symbol database
   (WinAntiDbg0x300.pdb), and an encrypted configuration file (config.bin).
2. The binary executable is compressed using the UPX 4.2.4 executable packer, concealing
   the internal import table and code sections until unpacked (upx -d).
3. Inspection of the unpacked binary and PDB symbols reveals advanced anti-debugging techniques:
   - DetectDebuggerAtLaunch()
   - EnableDebugPrivilege() (SeDebugPrivilege token adjustment)
   - Cross-process debugging attachment checks via DebugActiveProcess and DebugActiveProcessStop
   - Direct PEB inspection (BeingDebugged, NtGlobalFlag)
4. Dynamic and static control-flow analysis demonstrates that upon successfully passing
   all debugger detection barriers, the keystream buffer s1 undergoes exactly 12 cumulative rounds
   of the Hamming weight (popcount) cyclic alphabetic shift:
     s1[i] = 'a' + ((s1[i] - 'a' + popcount(i % 255)) % 26)
5. Function DecryptFlag() then computes the bitwise XOR between the 12-round shifted keystream s1
   and ciphertext buffer s2:
     flag[i] = s1[i] ^ s2[i]
6. Output flag:
   academy{Wind0ws_antid3bg_0x300_1415757f}
"""

import os
import sys
import zipfile
import urllib.request
import re

ZIP_URL = "https://challenge-files.cylabacademy.net/library/7a816a670d776e829de097d66432ea9a56d10385e37064193add756827163954/WinAntiDbg0x300.zip"
ZIP_PASSWORD = b"academy"

def solve(config_path: str = "") -> str:
    if not config_path or not os.path.exists(config_path):
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_431")
        os.makedirs(work_dir, exist_ok=True)
        config_path = os.path.join(work_dir, "config.bin")
        if not os.path.exists(config_path):
            zip_path = os.path.join(work_dir, "WinAntiDbg0x300.zip")
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

    # 12 rounds of cumulative popcount rotation on the valid un-debugged execution path
    rounds = 12
    print(f"[*] Simulating execution path ({rounds} rounds of popcount rotation)...")
    apply_shift(s1, rounds)

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
