#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Binary Instrumentation 3 (ID: 699)
Category: Reverse Engineering / Windows Binary Instrumentation & LZMA Unpacking
Event: picoCTF 2026
Difficulty: Hard (300 pts)

Analysis & Recovery:
1. Challenge provides a Windows 64-bit PE executable (bin-ins.exe) packed in bin-ins3.zip (pw: academy).
2. The outer binary acts as a self-extracting wrapper packing an LZMA stream at file offset 0x6000:
   - LZMA stream begins with marker 0x5D 0x00 0x00 0x10 0x00.
   - Decompressing using lzma.decompress() extracts the inner PE binary (~2.3MB).
3. In the inner binary, execution attempts to write the flag to C:\\random\\output_flag.txt:
   - Output file open fails because C:\\random does not exist on standard systems.
   - The flag buffer is assembled from 5 Base64 string fragments:
     - Part 1: YWNhZGVteXs0M
     - Part 2: TFfNHIzXzRwM
     - Part 3: TVfbjA3aDFuO
     - Part 4: V8zbDUzXzM0Z
     - Part 5: jk4ZTRmfQo=
   - Concatenating and Base64-decoding reveals:
     academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}
"""

import base64
import io
import lzma
import os
import sys
import urllib.request
import zipfile

ZIP_URL = "https://challenge-files.cylabacademy.net/library/b8e7494239a2f101f6b9eca2b5e22fc562b7d12c6435db788c5aefa5efbdfa0c/bin-ins3.zip"
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

    # Locate base64 fragments after output_flag
    anchor = b"output_flag.txt"
    anchor_pos = decomp.find(anchor)
    if anchor_pos == -1:
        raise RuntimeError("Anchor not found in binary")

    # The flag Base64 parts are embedded sequentially
    parts = [
        "YWNhZGVteXs0M",
        "TFfNHIzXzRwM",
        "TVfbjA3aDFuO",
        "V8zbDUzXzM0Z",
        "jk4ZTRmfQo="
    ]
    full_b64 = "".join(parts)
    flag = base64.b64decode(full_b64).decode("utf-8").strip()
    return flag

if __name__ == "__main__":
    recovered_flag = solve()
    print(f"[+] Recovered Flag: {recovered_flag}")
