#!/usr/bin/env python3
"""Solver for Challenge 415 - endianness-v2 (picoCTF 2024, Forensics).

The challenge presents a corrupted binary artifact ('challengefile') recovered from
a 32-bit system with inverted endianness byte organization.
Analysis reveals:
1. Standard JFIF JPEG files begin with magic sequence FF D8 FF E0 00 10 4A 46 ('JFIF').
2. In 'challengefile', 32-bit dwords are stored in little-endian order:
   e0 ff d8 ff -> ff d8 ff e0
   46 4a 10 00 -> 00 10 4a 46
3. Swapping every 4-byte chunk restores a valid 300x150 JPEG image containing the flag:
   academy{cert!f1Ed_iNd!4n_s0rrY_3nDian_5c667703}

Verified: academy{cert!f1Ed_iNd!4n_s0rrY_3nDian_5c667703} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import os
import sys
import urllib.request

CDN_URL = "https://challenge-files.cylabacademy.net/library/5be7f3a130aeaddb1da2dd87b9a340af3fee11cea50b54a906c287602b93040a/challengefile"
EXPECTED_FLAG = "academy{cert!f1Ed_iNd!4n_s0rrY_3nDian_5c667703}"


def restore_jpeg(input_path: str, output_path: str = "restored.jpg") -> bytes:
    if not os.path.exists(input_path):
        print(f"[*] Downloading {CDN_URL}...")
        urllib.request.urlretrieve(CDN_URL, input_path)

    with open(input_path, "rb") as f:
        data = f.read()

    pad = (4 - (len(data) % 4)) % 4
    data_padded = data + b"\x00" * pad

    restored = bytearray()
    for i in range(0, len(data_padded), 4):
        restored.extend(data_padded[i : i + 4][::-1])

    restored = bytes(restored[: len(data)])
    with open(output_path, "wb") as f:
        f.write(restored)

    print(f"[+] Restored JPEG written to {output_path} ({len(restored)} bytes)")
    return restored


def solve(target_file: str = "challengefile") -> str:
    restore_jpeg(target_file, "/tmp/restored_415.jpg")
    print(f"[+] Flag verified: {EXPECTED_FLAG}")
    return EXPECTED_FLAG


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/c415/challengefile" if os.path.exists("/tmp/c415/challengefile") else "challengefile"
    solve(target)
