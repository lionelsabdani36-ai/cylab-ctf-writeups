#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: MSB (ID: 359)
Category: Forensics / Steganography & Most Significant Bit Extraction
Event: picoCTF 2023
Difficulty: Medium (200 pts)

Analysis & Recovery:
1. The image is a 1074x1500 8-bit RGB PNG file.
2. Standard LSB (Least Significant Bit) steganography checks pass because the payload
   is embedded in the Most Significant Bit (MSB, bit 7) of each color channel.
3. Pure Python implementation: parse PNG chunks (IHDR, IDAT), decompress IDAT scanlines
   via zlib, reconstruct scanline filter passes (None, Sub, Up, Average, Paeth),
   extract the MSB of each RGB channel, pack into bytes, and search for the flag regex.
"""

import os
import re
import struct
import urllib.request
import zlib

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/5571b8de805ce3a5fae6bcd308a176bb328c5e867ad133dd853d2752abfe3f86/Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png"

def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    elif pb <= pc:
        return b
    else:
        return c

def solve(image_path: str = "") -> str:
    if not image_path:
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_359")
        os.makedirs(work_dir, exist_ok=True)
        image_path = os.path.join(work_dir, "Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png")
        if not os.path.exists(image_path):
            print(f"[*] Downloading {IMAGE_URL}...")
            urllib.request.urlretrieve(IMAGE_URL, image_path)

    print("[*] Reading and parsing PNG chunks...")
    with open(image_path, "rb") as f:
        png_bytes = f.read()

    assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n", "Invalid PNG header"
    pos = 8
    idat_chunks = []
    width, height = 0, 0

    while pos < len(png_bytes):
        length, ctype = struct.unpack(">I4s", png_bytes[pos:pos+8])
        cdata = png_bytes[pos+8:pos+8+length]
        pos += 12 + length
        if ctype == b"IHDR":
            width, height, bitdepth, colortype = struct.unpack(">IIBB", cdata[:10])
            assert bitdepth == 8 and colortype == 2, "Expected 8-bit truecolor RGB"
        elif ctype == b"IDAT":
            idat_chunks.append(cdata)

    print(f"[*] Decompressing IDAT payload ({width}x{height} RGB)...")
    raw = zlib.decompress(b"".join(idat_chunks))
    bpp = 3
    line_len = 1 + width * bpp

    print("[*] Reconstructing PNG scanlines (unfiltering)...")
    recon = bytearray(height * width * bpp)
    for y in range(height):
        filter_type = raw[y * line_len]
        line_raw = raw[y * line_len + 1 : (y + 1) * line_len]
        recon_prev = recon[(y - 1) * width * bpp : y * width * bpp] if y > 0 else None
        line_recon = bytearray(width * bpp)
        for x in range(width * bpp):
            filt_x = line_raw[x]
            a = line_recon[x - bpp] if x >= bpp else 0
            b = recon_prev[x] if recon_prev else 0
            c = recon_prev[x - bpp] if (recon_prev and x >= bpp) else 0
            if filter_type == 0:
                val = filt_x
            elif filter_type == 1:
                val = filt_x + a
            elif filter_type == 2:
                val = filt_x + b
            elif filter_type == 3:
                val = filt_x + ((a + b) // 2)
            elif filter_type == 4:
                val = filt_x + paeth(a, b, c)
            else:
                raise ValueError(f"Unknown PNG filter {filter_type}")
            line_recon[x] = val & 0xFF
        recon[y * width * bpp : (y + 1) * width * bpp] = line_recon

    print("[*] Extracting MSB (bit 7) stream...")
    bits = [(byte >> 7) & 1 for byte in recon]
    extracted = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        extracted.append(byte_val)

    print("[*] Searching for flag patterns...")
    pattern = re.compile(rb"(?:academy|picoCTF|CTF)\{[^\}]+\}")
    match = pattern.search(bytes(extracted))
    if not match:
        raise RuntimeError("Flag pattern not found in MSB stream")
    flag = match.group(0).decode("latin-1")
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"Recovered Flag: {flag}")
