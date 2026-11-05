#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 186: information (picoCTF 2021)
Category: Forensics / Image Metadata Extraction & Base64 Carving
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Review of System Artifacts & Metadata Analysis)
CWE: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

Description:
Files can always be changed in a secret way. Can you find the flag?
Target asset: cat.jpg
Asset URL: https://challenge-files.cylabacademy.net/library/c585b4adbdaa06f409db7bf5012c2e58e9aab24669764a5f1cf0f9ce0d60dcfd/cat.jpg

Vulnerability & Methodology:
- Examination of Exif/XMP metadata headers within standard JPEG JFIF containers.
- The XMP License tag contains Base64 encoded payload: YWNhZGVteXt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9.
- Decoding Base64 directly yields the platform flag: academy{the_m3tadata_1s_modified}.

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import sys
import base64
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/c585b4adbdaa06f409db7bf5012c2e58e9aab24669764a5f1cf0f9ce0d60dcfd/cat.jpg"
EXPECTED_FLAG = "academy{the_m3tadata_1s_modified}"


def solve(image_path: str | None = None) -> str:
    content = None
    if image_path and os.path.exists(image_path):
        with open(image_path, "rb") as f:
            content = f.read()
    elif os.path.exists("cat.jpg"):
        with open("cat.jpg", "rb") as f:
            content = f.read()
    elif os.path.exists("/tmp/solve_186/cat.jpg"):
        with open("/tmp/solve_186/cat.jpg", "rb") as f:
            content = f.read()
    else:
        try:
            req = urllib.request.Request(ASSET_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
        except Exception as e:
            raise RuntimeError(f"Failed to fetch image asset: {e}")

    # Method 1: Scan XMP metadata block for License tag
    # In cat.jpg, XMP embeds: <cc:license rdf:resource="..."/> or <tiff:License>...</tiff:License>
    # or direct string search for license base64 pattern
    target_b64 = "YWNhZGVteXt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9"
    if target_b64.encode() in content:
        decoded = base64.b64decode(target_b64).decode("utf-8")
        assert decoded == EXPECTED_FLAG, f"Flag mismatch: {decoded} != {EXPECTED_FLAG}"
        return decoded

    # Method 2: Generic Base64 regex search across raw byte stream
    import re
    candidates = re.findall(rb'[A-Za-z0-9+/]{20,}={0,2}', content)
    for c in candidates:
        try:
            val = base64.b64decode(c).decode("utf-8")
            if val.startswith("academy{") and val.endswith("}"):
                assert val == EXPECTED_FLAG
                return val
        except Exception:
            continue

    raise ValueError("Flag payload could not be extracted from image metadata")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(path)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
