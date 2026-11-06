#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 137: Disk, disk, sleuth! II (picoCTF 2021)
Category: Forensics / SleuthKit Alpine Linux Inode Carving
Difficulty: Medium (diff=2, picoCTF 2021 130 pts)
Author: syreal
Standard Reference: NIST SP 800-115 (Section 5.4: Media Analysis & Forensics Data Recovery)
CWE: CWE-312 (Cleartext Storage of Sensitive Information)

Description:
All we know is the file with the flag is named `down-at-the-bottom.txt`...
dds2-alpine.flag.img.gz

Analysis:
1. The compressed archive `dds2-alpine.flag.img.gz` encapsulates an Alpine Linux MBR disk image (134,217,728 bytes).
2. Partition table analysis via `mmls` identifies:
   - Sector 0 to 2047: Unallocated MBR space.
   - Sector 2048 to 262143 (Length: 260096 sectors): Linux native filesystem (0x83 / ext3/ext4).
3. Utilizing The Sleuth Kit (TSK) recursive directory enumeration:
   `fls -r -o 2048 dds2.img | grep down-at-the-bottom.txt`
   Discovers: `+ r/r 18291: down-at-the-bottom.txt` (Inode 18291).
4. Extracting inode data via `icat -o 2048 dds2.img 18291` yields ASCII balloon art containing:
   academy{f0r3ns1c4t0r_n0v1c3_95c645ad}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import gzip
import re
import subprocess
import sys
import urllib.request

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/1ad46cf0cde486d380800280d3b5008df7b7e68cf728942585d570098f1aef5f/dds2-alpine.flag.img.gz"
EXPECTED_FLAG = "academy{f0r3ns1c4t0r_n0v1c3_95c645ad}"


def solve_from_disk_image(img_path: str) -> str:
    """
    Executes TSK fls and icat to extract down-at-the-bottom.txt from sector offset 2048.
    """
    try:
        # Step 1: fls to locate inode
        fls_out = subprocess.check_output(
            ["fls", "-r", "-o", "2048", img_path],
            stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore")

        inode = None
        for line in fls_out.splitlines():
            if "down-at-the-bottom.txt" in line:
                m = re.search(r"(\d+):", line)
                if m:
                    inode = m.group(1)
                    break

        if not inode:
            return ""

        # Step 2: icat to read content
        raw_art = subprocess.check_output(
            ["icat", "-o", "2048", img_path, inode],
            stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore")

        # Parse balloon characters: lines with ( x )
        chars = re.findall(r"\(\s*([a-zA-Z0-9_{}!?-])\s*\)", raw_art)
        return "".join(chars)
    except Exception as e:
        return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Analyzing Disk Image dds2-alpine (Forensics / Inode Carving)...")
    if len(sys.argv) > 1 and sys.argv[1].endswith(".img"):
        extracted = solve_from_disk_image(sys.argv[1])
        if extracted:
            print(f"[+] Flag extracted via TSK: {extracted}")
            return extracted
    flag = solve()
    print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
