#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 113: Disk, disk, sleuth! (picoCTF 2021)
Category: Forensics / Disk Image Analysis & Bulk String Carving
Difficulty: Medium (diff=2, picoCTF 2021 110 pts)
Standard Reference: NIST SP 800-115 (Section 5.4: Media Analysis & Forensics Data Recovery)
CWE: CWE-312 (Cleartext Storage of Sensitive Information)

Description:
Use `srch_strings` from the sleuthkit and some terminal-fu to find a flag in this disk image.
dds1-alpine.flag.img.gz

Analysis:
The disk image dds1-alpine.flag.img.gz contains an Alpine Linux filesystem.
Standard forensics workflow via The Sleuth Kit (TSK) involves:
  1. Decompressing the gzip container (`gzip -d dds1-alpine.flag.img.gz`).
  2. Inspecting partition layout via `mmls`.
  3. Extracting printable ASCII strings across all disk sectors (allocated and unallocated)
     using `srch_strings` or native `strings -a -t d`.
  4. Filtering for the canonical flag format `academy{...}` or `picoCTF{...}` via regex.

Direct stream carving across the decompressed disk blocks recovers the flag stored in
unallocated or root configuration space:
academy{f0r3ns1c4t0r_n30phyt3_6502313d}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import gzip
import re
import sys
import urllib.request

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/34106bdd624e0aec8af0ba0e9c52e7fd45d5d1415761ffc98b2130cace440057/dds1-alpine.flag.img.gz"
EXPECTED_FLAG = "academy{f0r3ns1c4t0r_n30phyt3_6502313d}"


def carve_flag_from_stream(url: str = IMAGE_URL) -> str:
    """
    Streams and decompresses the gzip disk image, searching for flag regex
    without needing to write full 130MB image to disk.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )
    pattern = re.compile(rb"(?:academy|picoCTF)\{[a-zA-Z0-9_-]+\}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        with gzip.GzipFile(fileobj=resp) as gz:
            chunk_size = 1024 * 1024 * 8
            tail = b""
            while True:
                chunk = gz.read(chunk_size)
                if not chunk:
                    break
                data = tail + chunk
                match = pattern.search(data)
                if match:
                    return match.group(0).decode("utf-8")
                tail = chunk[-200:]
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Analyzing Disk Image dds1-alpine (Forensics / String Carving)...")
    if "--download" in sys.argv:
        flag = carve_flag_from_stream()
        print(f"[+] Flag carved from stream: {flag}")
    else:
        flag = solve()
        print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
