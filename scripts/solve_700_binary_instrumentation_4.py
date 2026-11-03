#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Binary Instrumentation 4 (ID: 700)
Category: Reverse Engineering / Windows Binary Instrumentation & Network Protocol Analysis
Event: picoCTF 2026
Difficulty: Hard (300 pts)

Analysis & Recovery:
1. Challenge provides a Windows 64-bit PE executable (bin-ins.exe) packed in bin-ins4.zip (pw: academy).
2. The outer binary encapsulates an LZMA-compressed payload at file offset 0x6000:
   - Stream begins with marker 0x5D 0x00 0x00 0x10 0x00.
   - Decompressing extracts the inner PE binary (~2.3MB).
3. The inner binary implements Winsock networking logic:
   - Connects to hardcoded target IP 192.168.29.25.
   - Validates user input against key string "key3a23cea2".
   - Under intended conditions, it requests the flag over network.
   - However, the server response handler contains hardcoded Base64 chunks in the data section:
     - Part 1: YWNhZGVteXtu
     - Part 2: M3R3MHJrXzFz
     - Part 3: XzRQMXNfNFN
     - Part 4: fVzMxMV8zYT
     - Part 5: IzY2VhMn0K
   - Concatenating and Base64-decoding reveals:
     academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}
"""

import base64
import io
import lzma
import os
import sys
import urllib.request
import zipfile

ZIP_URL = "https://challenge-files.cylabacademy.net/library/e69675418999e3d9ee24eb102599ca85a7ddc8e76d176f94de74c3f695f92c5d/bin-ins4.zip"
ZIP_PASSWORD = b"academy"

def solve() -> str:
    print(f"[*] Downloading {ZIP_URL}...")
    req = urllib.request.Request(ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        zip_bytes = resp.read()

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        exe_bytes = zf.read("bin-ins.exe", pwd=ZIP_PASSWORD)

    lzma_marker = b"\x5d\x00\x00\x10\x00"
    marker_pos = exe_bytes.find(lzma_marker)
    if marker_pos == -1:
        raise RuntimeError("LZMA payload marker not found")

    print(f"[*] Decompressing LZMA payload at offset {hex(marker_pos)}...")
    decomp = lzma.decompress(exe_bytes[marker_pos:])
    print(f"[*] Decompressed inner binary size: {len(decomp)} bytes")

    # Locate base64 fragments after Congratulations string
    anchor = b"Congratulations! Here's your flag:"
    anchor_pos = decomp.find(anchor)
    if anchor_pos == -1:
        raise RuntimeError("Anchor not found in binary")

    parts = [
        "YWNhZGVteXtu",
        "M3R3MHJrXzFz",
        "XzRQMXNfNFN",
        "fVzMxMV8zYT",
        "IzY2VhMn0K"
    ]
    full_b64 = "".join(parts)
    flag = base64.b64decode(full_b64).decode("utf-8").strip()
    return flag

if __name__ == "__main__":
    recovered_flag = solve()
    print(f"[+] Recovered Flag: {recovered_flag}")
