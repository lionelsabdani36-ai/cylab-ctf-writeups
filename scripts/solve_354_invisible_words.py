#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 354: Invisible WORDs (picoCTF 2023)
Category: Forensics
Author: LT 'syreal' Jones
Points: 300

Technical Analysis:
1. The target artifact is a Windows BMP 32-bit image (`output.bmp`), 960x540 pixels.
2. In 32-bit BMP, pixels are encoded in 4-byte chunks (BGRA: Blue, Green, Red, Alpha).
3. Steganography analysis reveals interleaved payload data hidden across 16-bit WORD boundaries:
   - Beginning at offset 0x8c, every 4-byte group consists of:
     - 2 bytes of payload (Blue and Green color channel / low WORD)
     - 2 bytes of cover pixel data (Red and Alpha channel / high WORD)
4. Extracting the alternating 2-byte WORDs yields a ZIP archive starting with magic `PK\x03\x04`.
5. Locating the End of Central Directory (EOCD, `PK\x05\x06`) truncates trailing image padding.
6. The unpacked archive contains `ZnJhbmtlbnN0ZWluLXRlc3QudHh0` (Mary Shelley's Frankenstein text),
   which hides the flag: `academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}`.

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import os
import sys
import io
import re
import zipfile
import urllib.request

EXPECTED_FLAG = "academy{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_75527d56}"
ASSET_URL = "https://challenge-files.cylabacademy.net/library/72bf5142480ae4202c068e306133a1d73c060bb4eaaba1ef308fb6dcae1c98d7/output.bmp"

def get_bmp_bytes():
    possible_paths = [
        "output.bmp",
        os.path.join(os.path.dirname(__file__), "output.bmp"),
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_354/output.bmp"
    ]
    for p in possible_paths:
        if os.path.exists(p):
            with open(p, "rb") as f:
                return f.read()

    print(f"[*] Downloading BMP from {ASSET_URL}...")
    req = urllib.request.Request(ASSET_URL, headers={
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://learn.cylabacademy.org/challenges"
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()

def solve():
    bmp_data = get_bmp_bytes()
    assert len(bmp_data) > 0x8c, "Invalid BMP file size"

    # Extract 2-byte WORDs interleaved every 4 bytes starting at 0x8c
    extracted = bytearray()
    for i in range(0x8c, len(bmp_data), 4):
        extracted.extend(bmp_data[i:i+2])

    assert extracted.startswith(b"PK\x03\x04"), "ZIP signature PK\\x03\\x04 not found at expected position"

    # Locate End of Central Directory (EOCD) record to cleanly truncate padding
    eocd_idx = extracted.rfind(b"PK\x05\x06")
    assert eocd_idx != -1, "EOCD record not found in extracted ZIP stream"

    comment_len = int.from_bytes(extracted[eocd_idx+20:eocd_idx+22], "little")
    zip_bytes = bytes(extracted[:eocd_idx + 22 + comment_len])

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for fname in z.namelist():
            text_content = z.read(fname)
            m = re.search(rb"(?:academy|picoCTF|CTF)\{[^}]+\}", text_content)
            if m:
                flag = m.group(0).decode("utf-8")
                print(f"[+] Found flag in {fname}: {flag}")
                assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
                return flag

    raise RuntimeError("Flag not found inside unzipped contents")

if __name__ == "__main__":
    solve()
