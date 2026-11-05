#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 44: Glory of the Garden (picoCTF 2019)
Category: Forensics / Steganographic Data Carving & JPEG File Trailing Analysis
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Artifact Analysis & Digital Forensics), ISO/IEC 10918-1 (JPEG/JFIF EOI Marker)
CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

Description:
This file contains more than it seems.
Get the flag from garden.jpg.

Methodology:
- JPEG specifications (ISO/IEC 10918-1) define the file boundary from SOI (0xFF 0xD8) to EOI (0xFF 0xD9).
- Arbitrary payload or text data appended beyond the 0xFF 0xD9 marker is ignored by standard image decoders.
- Binary extraction / strings inspection recovers trailing plaintext payload:
  "Here is a flag: academy{more_than_m33ts_the_3y3ff3b9e86}"
- Flag format: academy{more_than_m33ts_the_3y3ff3b9e86}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import sys
import urllib.request

IMAGE_URL = (
    "https://challenge-files.cylabacademy.net/library/"
    "3c60c5a7f7a8067606c51d4b4b3c7913fae709b11e2f2c7adbc0a0b4cda452ff/garden.jpg"
)
LOCAL_CACHE = "/tmp/cylab_garden.jpg"
EXPECTED_FLAG = "academy{more_than_m33ts_the_3y3ff3b9e86}"


def download_or_load(image_path: str = LOCAL_CACHE) -> bytes:
    if os.path.exists(image_path) and os.path.getsize(image_path) > 0:
        with open(image_path, "rb") as f:
            return f.read()

    req = urllib.request.Request(
        IMAGE_URL,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://learn.cylabacademy.org/challenges",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()

    with open(image_path, "wb") as f:
        f.write(data)
    return data


def solve(image_path: str = LOCAL_CACHE) -> str:
    data = download_or_load(image_path)

    # Search for flag pattern in binary content
    match = re.search(rb"(academy\{[a-zA-Z0-9_]+\})", data)
    if not match:
        raise ValueError("Flag pattern not found in target image data")

    flag = match.group(1).decode("utf-8")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else LOCAL_CACHE
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
