#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 74: What Lies Within (picoCTF 2019)
Category: Forensics / Image LSB Steganography & Bitplane Extraction
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.2: Target Analysis & Document Carving)
CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

Description:
There's something in the building. Can you retrieve the flag?
- Asset: buildings.png

Methodology:
- Portable Network Graphics (PNG) is a lossless bitmap format defined in RFC 2083 / ISO/IEC 15948.
- Digital image steganography hides arbitrary bit streams inside the least significant bits (LSB)
  of RGB color channels, resulting in pixel variations indistinguishable to the human eye.
- For each pixel across raster scanlines (y in 0..h-1, x in 0..w-1), extract LSB of R, G, and B.
- Reconstruct contiguous 8-bit octets:
  b0 b1 b2 b3 b4 b5 b6 b7 -> byte
- Decoding the resulting byte stream recovers the embedded ASCII message:
  academy{h1d1ng_1n_th3_b1t5}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import io
import os
import re
import sys
import urllib.request
from PIL import Image

ASSET_URL = "https://challenge-files.cylabacademy.net/library/5235bfccd8f3cc2d059ee828f774846542f28f7ec66cb4f0c6ceb536c38026d4/buildings.png"
EXPECTED_FLAG = "academy{h1d1ng_1n_th3_b1t5}"


def solve(file_path: str | None = None) -> str:
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            data = f.read()
    elif os.path.exists("buildings.png"):
        with open("buildings.png", "rb") as f:
            data = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()

    img = Image.open(io.BytesIO(data)).convert("RGB")
    w, h = img.size
    px = img.load()
    assert px is not None, "Image pixel data could not be loaded"

    bits = []
    for y in range(h):
        for x in range(w):
            rgb = px[x, y]
            assert isinstance(rgb, tuple), "Pixel is not a tuple"
            r, g, b = rgb[:3]
            bits.extend((r & 1, g & 1, b & 1))

    extracted = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        extracted.append(byte)

    text = extracted.decode("latin1", errors="ignore")
    m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", text)
    if not m:
        raise ValueError("Failed to recover flag from PNG LSB steganography")

    raw_flag = m.group(0)
    assert raw_flag == EXPECTED_FLAG, f"Flag mismatch: {raw_flag} != {EXPECTED_FLAG}"
    return raw_flag


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target_file)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
