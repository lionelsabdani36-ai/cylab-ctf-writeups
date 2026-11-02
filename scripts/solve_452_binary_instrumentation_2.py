#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Binary Instrumentation 2 (ID: 452)
Category: Reverse Engineering / Windows Binary Instrumentation & LZMA Unpacking
Event: picoCTF 2025
Difficulty: Medium (300 pts)

Analysis & Recovery:
1. Challenge provides a Windows 64-bit PE executable (bininst2.exe) packed inside bininst2.zip.
2. The outer binary is protected with an LZMA-packed payload stored in the custom '.ATOM' section:
   - Section .ATOM starts at raw file offset 0x6000 with virtual size 0x6ade1 bytes.
   - Header begins with standard LZMA stream marker (0x5D 0x00 0x00 0x10 0x00).
   - Decompressing the stream via lzma.decompress() recovers the underlying 2.3MB inner executable.
3. Intended Dynamic Instrumentation Analysis:
   - The challenge scenario describes a program attempting to create a file and write the flag to it:
     "I swear this program was supposed to create a file and write the flag directly to the file.
     Can you try and intercept the file writing function to see what went wrong?"
   - The inner executable invokes Windows API file operations (CreateFileW, WriteFile) but uses an
     unconfigured template path ("<Insert path here>"), causing the file operation to fail at runtime.
   - The intended path is to hook WriteFile using dynamic binary instrumentation tools (such as Frida)
     to intercept the lpBuffer argument before the call fails.
4. Direct Static De-obfuscation:
   - Upon unpacking the LZMA stream from .ATOM, the inner binary's data section directly exposes the
     buffer intended for WriteFile:
     "YWNhZGVteXtmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9"
   - Decoding the Base64 payload directly recovers the competition flag:
     academy{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}
"""

import os
import sys
import zipfile
import urllib.request
import lzma
import base64
import re

ZIP_URL = "https://challenge-files.cylabacademy.net/library/ce8f745beda824c87d5482c853c90b7758b9a95d9b05db0c74fb2b0678f8115b/bininst2.zip"
ZIP_PASSWORD = b"academy"

def solve(exe_path: str = "") -> str:
    if not exe_path or not os.path.exists(exe_path):
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_452")
        os.makedirs(work_dir, exist_ok=True)
        exe_path = os.path.join(work_dir, "bininst2.exe")
        if not os.path.exists(exe_path):
            zip_path = os.path.join(work_dir, "bininst2.zip")
            if not os.path.exists(zip_path):
                print(f"[*] Downloading {ZIP_URL}...")
                urllib.request.urlretrieve(ZIP_URL, zip_path)
            print("[*] Extracting archive...")
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(work_dir, pwd=ZIP_PASSWORD)

    print(f"[*] Reading packed executable: {exe_path}...")
    with open(exe_path, "rb") as f:
        raw = f.read()

    # Search for .ATOM section or LZMA magic bytes
    lzma_marker = b"\x5d\x00\x00\x10\x00"
    marker_idx = raw.find(lzma_marker)
    if marker_idx == -1:
        raise RuntimeError("LZMA compressed payload marker not found in executable")

    print(f"[*] Found LZMA compressed stream at offset {hex(marker_idx)}...")
    lzma_data = raw[marker_idx:]

    print("[*] Decompressing inner PE payload...")
    decompressed = lzma.decompress(lzma_data)
    print(f"[*] Inner executable extracted ({len(decompressed)} bytes)")

    # Extract Base64 flag string (Base64 encoding of academy{...})
    m_b64 = re.search(rb"YWNhZGVte[A-Za-z0-9+/=]+", decompressed)
    if m_b64:
        b64_str = m_b64.group(0).decode("ascii")
        flag = base64.b64decode(b64_str).decode("ascii")
        print(f"[*] Decoded Base64 payload: {flag}")
        return flag

    # Fallback to direct flag pattern search
    m_flag = re.search(rb"(?:academy|picoCTF|CTF)\{[^}]+\}", decompressed)
    if m_flag:
        flag = m_flag.group(0).decode("latin-1")
        return flag

    raise RuntimeError("Flag string not found in inner payload")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    recovered_flag = solve(target)
    print(f"Recovered Flag: {recovered_flag}")
