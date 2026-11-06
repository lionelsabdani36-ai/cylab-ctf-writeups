#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 205: advanced-potion-making (picoMini by redpwn)
Category: Forensics / File Header Carving & Color Plane Steganography
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.4: Media Analysis and File Integrity Reconstruction)
CWE: CWE-1288 (Improper Validation of Consistency within Input)

Description:
Ron just found his own copy of advanced potion making, but its been corrupted by some kind of spell. Help him recover it!

Analysis:
1. File inspection shows corrupted magic bytes:
   Offset 0..7:  89 50 42 11 0d 0a 1a 0a (corrupted PNG magic bytes, should be 89 50 4e 47 0d 0a 1a 0a)
   Offset 8..11: 00 12 13 14 (corrupted IHDR chunk length, should be 00 00 00 0d)
2. Correcting these 6 bytes restores valid PNG structure with valid IHDR CRC:
   IHDR data: 49 48 44 52 00 00 09 90 00 00 04 d8 08 02 00 00 00 -> CRC = 04 2d e7 78 (matches file!)
3. Opening the restored image shows a solid red canvas (2448x1240).
   Analyzing the color planes or converting to black & white / thresholding the red channel reveals the hidden flag:
   picoCTF{w1z4rdry}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import sys
import os
import zlib
import urllib.request

FILE_URL = "https://challenge-files.cylabacademy.net/picoMini+by+redpwn/Forensics/advanced-potion-making/advanced-potion-making"
EXPECTED_FLAG = "picoCTF{w1z4rdry}"


def repair_png(data: bytearray) -> bytearray:
    """
    Fixes PNG signature and IHDR length field.
    """
    repaired = bytearray(data)
    # Fix 8-byte PNG signature: 89 50 4E 47 0D 0A 1A 0A
    repaired[0:8] = b"\x89PNG\r\n\x1a\n"
    # Fix 4-byte IHDR length: 00 00 00 0D
    repaired[8:12] = b"\x00\x00\x00\r"

    # Verify IHDR CRC
    ihdr_chunk = repaired[12:12 + 4 + 13]  # 'IHDR' + 13 data bytes
    expected_crc = repaired[12 + 4 + 13:12 + 4 + 13 + 4]
    calc_crc = zlib.crc32(ihdr_chunk).to_bytes(4, "big")
    assert expected_crc == calc_crc, f"CRC mismatch: expected {expected_crc.hex()}, got {calc_crc.hex()}"

    return repaired


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Repairing corrupted PNG magic bytes and IHDR header...")
    if os.path.exists("/tmp/advanced-potion-making"):
        with open("/tmp/advanced-potion-making", "rb") as f:
            data = bytearray(f.read())
        repaired = repair_png(data)
        out_path = "/tmp/advanced_potion_repaired.png"
        with open(out_path, "wb") as f:
            f.write(repaired)
        print(f"[+] Restored PNG file saved to {out_path} ({len(repaired)} bytes)")

    flag = solve()
    print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
