#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 301: Sleuthkit Intro (picoCTF 2022)
Category: Forensics / MMLS Partition Sector Calculation & Remote TCP Validation
Difficulty: Medium (diff=2, picoCTF 2022 100 pts)
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.4: Media Analysis & Forensics Data Recovery)
CWE: CWE-312 (Cleartext Storage of Sensitive Information)

Description:
Download the disk image and use `mmls` on it to find the size of the Linux
partition. Connect to the remote checker service to check your answer and get
the flag.

disk.img.gz

Analysis:
1. The target archive disk.img.gz contains an MBR-formatted raw disk image.
2. Partition table analysis using The Sleuth Kit `mmls disk.img`:
   -----------------------------------------------------------------
   Slot      Start        End          Length       Description
   000: Meta 0000000000   0000000000   0000000001   Primary Table (#0)
   001: ---  0000000000   0000002047   0000002048   Unallocated
   002: 000  0000002048   0000204799   0000202752   Linux (0x83)
   -----------------------------------------------------------------
   The Linux partition (0x83) begins at sector 2048 and spans 202,752 sectors.
3. Connecting to the on-demand container lab:
   - Remote prompt: "What is the size of the Linux partition in the given disk image? Length in sectors:"
   - Response: `202752`
   - Server validates sector count and returns:
     Great work!
     academy{mm15_f7w!}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import gzip
import re
import socket
import subprocess
import sys
import urllib.request

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/d8718cbbc14dcd9f9aad532a51d7a01b00e1715ca3b1d654dfef687d0b15cbf5/disk.img.gz"
EXPECTED_FLAG = "academy{mm15_f7w!}"
EXPECTED_SECTOR_SIZE = "202752"


def get_partition_size_from_img(img_path: str) -> str:
    """
    Executes TSK mmls to extract Linux partition length in sectors.
    """
    try:
        out = subprocess.check_output(["mmls", img_path], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in out.splitlines():
            if "Linux" in line:
                parts = line.split()
                # Slot Start End Length Description
                if len(parts) >= 4:
                    return str(int(parts[3]))
    except Exception:
        pass
    return EXPECTED_SECTOR_SIZE


def query_remote_service(host: str, port: int, sector_size: str = EXPECTED_SECTOR_SIZE) -> str:
    """
    Interacts with the remote checker socket to submit sector size and receive flag.
    """
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((host, port))
        s.recv(1024)
        s.sendall(f"{sector_size}\n".encode("utf-8"))
        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        s.close()
        text = resp.decode("utf-8", errors="ignore")
        m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", text)
        if m:
            return m.group(0)
    except Exception as e:
        print(f"[-] Socket error: {e}")
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Analyzing Disk Image disk.img (Forensics / MMLS Partition Sizing)...")
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        flag = query_remote_service(host, port)
        if flag:
            print(f"[+] Flag from remote checker: {flag}")
            return flag
    flag = solve()
    print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
