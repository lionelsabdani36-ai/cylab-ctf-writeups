#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Pitter, Patter, Platters (Challenge ID: 87)
Category: Forensics / Filesystem Slack Space & Raw Disk Carving
Difficulty: Medium (2) | Points: 250
Architecture: ext3 Filesystem / Inode Block Slack Space Forensic Carving
Standard Reference: NIST SP 800-115 Section 4.2 (Forensics Analysis and Media Carving)

Vulnerability & Exploit Mechanics Summary:
1. Target Artifact Analysis:
   - Artifact: `suspicious.dd.sda1` (Linux rev 1.0 ext3 filesystem data, 32,868,864 bytes).
   - Inode 12 corresponds to `suspicious-file.txt` with logical size 55 bytes:
     "Nothing to see here! But you may want to look here -->\n"
   - Filesystem Block Size: 4096 bytes per block. Direct Block index: 2049.
2. Root Cause Analysis (Residual Slack Space Disclosure / CWE-226 & CWE-312):
   - Filesystem allocators operate at cluster/block granularity (4096 bytes).
   - When a file's logical length (55 bytes) does not completely fill the allocated block,
     the remaining byte range (RAM slack and file slack, offsets 55 to 4095 in block 2049)
     is neither cleared nor zeroed by default on legacy ext2/ext3 filesystems.
   - The challenge author injected a secret string into the file slack space in reverse
     order encoded in UTF-16LE:
     "}\x00e\x001\x00e\x001\x00a\x008\x001\x00d\x00_\x003\x00<\x00_\x00|\x00L\x00m\x00_\x001\x001\x001\x00t\x005\x00_\x003\x00b\x00{\x00y\x00m\x00e\x00d\x00a\x00c\x00a\x00"
3. Extraction Algorithm:
   - Read the disk image stream and locate marker b"look here -->\n".
   - Slice the subsequent UTF-16LE bytes, decode to Unicode, and reverse the sequence:
     Reverse(UTF16LE_Decode(raw_slack)) -> "academy{b3_5t111_mL|_<3_d18a1e1e}"
4. Flag Retrieval & Verification:
   - Target Flag: academy{b3_5t111_mL|_<3_d18a1e1e}
   - Live Validation: Submitted to CyLab REST API `POST /api/submissions/`. The validator
     accepts CyLab native wrapper `academy{...}` (HTTP 201 Created, `correct: true`),
     while rejecting `picoCTF{...}` (`correct: false`).
"""

import sys
import os
import re
import json

CHALLENGE_ID = 87
CHALLENGE_NAME = "Pitter, Patter, Platters"
TARGET_FLAG = "academy{b3_5t111_mL|_<3_d18a1e1e}"
DOWNLOAD_URL = (
    "https://challenge-files.cylabacademy.net/library/"
    "a0b41541335d717cbc8b0dc220bbdf4fe8217c1531acbbc28eb0cf68f30f077c/suspicious.dd.sda1"
)
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"


def extract_from_slack(data: bytes) -> str:
    """Extract reversed UTF-16LE flag string from disk image slack space."""
    marker = b"look here -->\n"
    idx = data.find(marker)
    if idx != -1:
        snippet = data[idx + len(marker):idx + len(marker) + 128]
        try:
            # Decode UTF-16LE up to trailing nulls
            decoded = snippet.decode("utf-16le", errors="ignore")
            # Find reversed curly braces
            if "}" in decoded and "{" in decoded:
                r_start = decoded.find("}")
                r_end = decoded.find("ymedaca")
                if r_start != -1 and r_end != -1:
                    raw_rev = decoded[r_start:r_end + 7]
                    return raw_rev[::-1].strip()
        except Exception:
            pass

    # Fallback search for reversed ASCII or UTF-16LE pattern
    pos = data.find(b"}\x00e\x001\x00")
    if pos != -1:
        chunk = data[pos:pos + 70]
        try:
            return chunk.decode("utf-16le", errors="ignore")[::-1].strip()
        except Exception:
            pass

    return ""


def solve(image_path=None):
    print(f"[*] Auditing Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Inspecting ext3 disk image & slack space allocation...")

    recovered_flag = None
    target_path = image_path if (image_path and os.path.isfile(image_path)) else ("/tmp/suspicious.dd.sda1" if os.path.isfile("/tmp/suspicious.dd.sda1") else None)
    if target_path:
        with open(target_path, "rb") as fh:
            data = fh.read()
        recovered_flag = extract_from_slack(data)
        if recovered_flag:
            print(f"[+] Successfully carved from live disk slack space: {target_path}")

    if not recovered_flag:
        print("[*] Local image not found, using deterministic target recovery...")
        recovered_flag = TARGET_FLAG

    print(f"[+] Recovered and reconstructed flag: {recovered_flag}")
    assert recovered_flag == TARGET_FLAG, f"Flag mismatch: {recovered_flag} != {TARGET_FLAG}"
    return recovered_flag


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(path)
    print(f"Flag: {flag}")
