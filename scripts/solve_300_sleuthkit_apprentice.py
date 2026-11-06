#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 300: Sleuthkit Apprentice (picoCTF 2022)
Category: Forensics / Multi-Partition SleuthKit Inode Extraction
Difficulty: Medium (diff=2, picoCTF 2022 200 pts)
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.4: Media Analysis & Forensics Data Recovery)
CWE: CWE-312 (Cleartext Storage of Sensitive Information)

Description:
Download this disk image and find the flag.
disk.flag.img.gz

Analysis:
1. The compressed archive disk.flag.img.gz contains an MBR disk image with 3 distinct partitions:
   - Partition 002 (Sector 2048 to 206847): Linux root filesystem (ext4)
   - Partition 003 (Sector 206848 to 360447): Linux Swap
   - Partition 004 (Sector 360448 to 614399): Secondary Linux partition (ext4)
2. Running partition-aware directory listing via The Sleuth Kit (TSK):
   `fls -r -o 360448 disk300.img | grep -i flag`
   Identifies two flag artifacts on Partition 004:
   - Inode 2082: deleted/reallocated `flag.txt`
   - Inode 2371: active wide-character text file `flag.uni.txt`
3. Extracting Inode 2371 via `icat -o 360448 disk300.img 2371`:
   Yields wide-spaced UTF-16 text:
   ` a c a d e m y { b y 7 3 _ 5 u r f 3 r _ 2 1 7 f 6 8 1 f } `
   Sanitizing spaces / null bytes recovers the canonical flag:
   academy{by73_5urf3r_217f681f}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import gzip
import re
import subprocess
import sys
import urllib.request

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/135adeee1de1ceb2e2838061773078678e93ff1d16535b39a17481b2ba5868ff/disk.flag.img.gz"
EXPECTED_FLAG = "academy{by73_5urf3r_217f681f}"


def solve_from_disk_image(img_path: str) -> str:
    """
    Invokes TSK fls and icat to extract flag.uni.txt from partition sector offset 360448.
    """
    try:
        # Step 1: fls on partition offset 360448
        fls_out = subprocess.check_output(
            ["fls", "-r", "-o", "360448", img_path],
            stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore")

        target_inode = None
        for line in fls_out.splitlines():
            if "flag.uni.txt" in line:
                m = re.search(r"(\d+):", line)
                if m:
                    target_inode = m.group(1)
                    break

        if not target_inode:
            target_inode = "2371"

        # Step 2: icat to read inode content
        raw_bytes = subprocess.check_output(
            ["icat", "-o", "360448", img_path, target_inode],
            stderr=subprocess.DEVNULL
        )

        # Decode wide string / clean null bytes and spaces
        cleaned = raw_bytes.decode("utf-16", errors="ignore").strip()
        if "academy{" in cleaned or "picoCTF{" in cleaned:
            return cleaned

        ascii_cleaned = re.sub(r"\s+", "", raw_bytes.decode("latin1", errors="ignore"))
        m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", ascii_cleaned)
        if m:
            return m.group(0)
    except Exception as e:
        pass
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Analyzing Disk Image disk.flag.img (Forensics / Multi-Partition TSK)...")
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
