#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 305: St3g0 (picoCTF 2022)
Category: Forensics / Image Steganography & LSB Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Steganography Detection & Binary Analysis)
CWE: CWE-312 (Cleartext Storage of Sensitive Information), CWE-200 (Exposure of Sensitive Information)

Description:
Download this image and find the flag.
Download image here: https://challenge-files.cylabacademy.net/library/f9cf770d7b39e9524e2be7e75cfa654af2ec8dd65c7f09f55093394e4e1d9f79/academy.flag.png
Hint: We know the end sequence of the message will be "$t3g0".

Methodology:
- Target asset: academy.flag.png (661x181 pixels, 8-bit RGBA, size: 20,956 bytes).
- Analysis reveals steganographic payload embedded in the Least Significant Bits (LSB)
  of the RGB color channels across scanlines (order: b1,rgb,lsb,xy).
- The solver implements pure Python standard library PNG chunk parsing, zlib IDAT
  decompression, scanline defiltering (None, Sub, Up, Average, Paeth), and bit reconstruction.
- Recovered flag: academy{7h3r3_15_n0_5p00n_7e497237} with trailer "$t3g0".

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import struct
import sys
import urllib.request
import zlib

ASSET_URL = "https://challenge-files.cylabacademy.net/library/f9cf770d7b39e9524e2be7e75cfa654af2ec8dd65c7f09f55093394e4e1d9f79/academy.flag.png"
EXPECTED_FLAG = "academy{7h3r3_15_n0_5p00n_7e497237}"


def extract_lsb_from_png(png_bytes: bytes) -> str:
    # 1. Parse PNG chunks
    if not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Invalid PNG magic bytes")

    pos = 8
    width, height = 0, 0
    colortype = 6
    idat_data = b""

    while pos < len(png_bytes):
        length, ctype = struct.unpack(">I4s", png_bytes[pos : pos + 8])
        pos += 8
        cdata = png_bytes[pos : pos + length]
        pos += length + 4  # skip data + 4 bytes CRC
        if ctype == b"IHDR":
            width, height, bitdepth, colortype, comp, filt, inter = struct.unpack(">IIBBBBB", cdata)
        elif ctype == b"IDAT":
            idat_data += cdata
        elif ctype == b"IEND":
            break

    decomp = zlib.decompress(idat_data)
    bytes_per_pixel = 4 if colortype == 6 else 3
    stride = 1 + width * bytes_per_pixel

    recon = bytearray()
    prev_line = bytearray(width * bytes_per_pixel)

    for y in range(height):
        line = decomp[y * stride : (y + 1) * stride]
        ftype = line[0]
        raw = bytearray(line[1:])
        curr = bytearray(width * bytes_per_pixel)

        if ftype == 0:  # None
            curr = raw
        elif ftype == 1:  # Sub
            for x in range(width * bytes_per_pixel):
                left = curr[x - bytes_per_pixel] if x >= bytes_per_pixel else 0
                curr[x] = (raw[x] + left) & 0xFF
        elif ftype == 2:  # Up
            for x in range(width * bytes_per_pixel):
                up = prev_line[x]
                curr[x] = (raw[x] + up) & 0xFF
        elif ftype == 3:  # Average
            for x in range(width * bytes_per_pixel):
                left = curr[x - bytes_per_pixel] if x >= bytes_per_pixel else 0
                up = prev_line[x]
                curr[x] = (raw[x] + ((left + up) >> 1)) & 0xFF
        elif ftype == 4:  # Paeth
            for x in range(width * bytes_per_pixel):
                a = curr[x - bytes_per_pixel] if x >= bytes_per_pixel else 0
                b = prev_line[x]
                c = prev_line[x - bytes_per_pixel] if x >= bytes_per_pixel else 0
                p = a + b - c
                pa = abs(p - a)
                pb = abs(p - b)
                pc = abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                curr[x] = (raw[x] + pr) & 0xFF

        prev_line = curr
        recon.extend(curr)

    # Extract LSB of RGB channels (skipping Alpha if 4 bytes per pixel)
    bits = []
    for i in range(0, len(recon), bytes_per_pixel):
        r, g, b = recon[i], recon[i + 1], recon[i + 2]
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        val = 0
        for j in range(8):
            val |= bits[i + j] << (7 - j)
        out.append(val)

    m = re.search(rb"(?:academy|picoCTF)\{[^}]+\}", out)
    if not m:
        raise ValueError("Flag pattern not found in LSB bitstream")

    return m.group(0).decode("utf-8", errors="ignore")


def solve(file_path: str | None = None) -> str:
    png_bytes = b""
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            png_bytes = f.read()
    elif os.path.exists("academy.flag.png"):
        with open("academy.flag.png", "rb") as f:
            png_bytes = f.read()
    elif os.path.exists("/tmp/stego_305/academy.flag.png"):
        with open("/tmp/stego_305/academy.flag.png", "rb") as f:
            png_bytes = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            png_bytes = resp.read()

    flag = extract_lsb_from_png(png_bytes)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
