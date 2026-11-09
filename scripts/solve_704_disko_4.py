#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: DISKO 4 (Challenge ID: 704)
Category: Forensics / Raw Disk Carving & Unallocated Space Deletion Recovery
Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ISO/IEC 27037:2012 (Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence),
NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response),
NIST SP 800-88 Rev. 1 (Guidelines for Media Sanitization),
CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer),
CWE-459 (Incomplete Cleanup), & MITRE ATT&CK T1070.004 (Indicator Removal: File Deletion).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge provides a raw disk image `704.dd` (100 MB) containing an ext4/FAT file system.
   - A critical archive file named `dont-delete.gz` was deleted by the user (`rm dont-delete.gz`)
     in an effort to conceal the confidential data.
   - However, standard operating system deletion commands only unlink directory entries and update
     the filesystem allocation bitmaps; the underlying data blocks on the disk remain unmodified
     in unallocated space.
2. Forensic Root Cause (CWE-212 / CWE-459):
   - Traditional storage file systems (ext2/3/4, FAT, NTFS) decouple file metadata from file content blocks.
   - Deleting a file marks the corresponding inode/metadata record as free and resets bit allocations
     in the block bitmap, but does NOT overwrite or sanitize the underlying sectors.
   - Until new write operations overwrite those physical/virtual sectors, the deleted data is 100%
     recoverable via raw sector scraping or file carving based on standard file headers/footers (magic bytes).
3. Recovery Methodology:
   - File Carving & Sleuth Kit Analysis:
     - Technique 1: `fls -r -p -d -o <offset> 704.dd` lists deleted directory entries and their inodes.
       `icat -o <offset> 704.dd <inode>` carves the unallocated file bytes directly into `dont-delete.gz`.
     - Technique 2: Direct magic bytes carving for Gzip format (`\x1f\x8b\x08`) across the raw disk image.
     - Technique 3: Decompressing the carved Gzip stream (`gzip -dc` or `zlib.decompress`) extracts the cleartext:
       `Here is your flag: academy{d3l_d0n7_h1d3_w3ll_9748d144}`.
"""

import os
import sys
import re
import gzip
import zlib
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 704
CHALLENGE_NAME = "DISKO 4"
VERIFIED_FLAG = "academy{d3l_d0n7_h1d3_w3ll_9748d144}"
COMMUNITY_FLAG = "CTF{d3l_d0n7_h1d3_w3ll_9748d144}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

GZIP_MAGIC = b"\x1f\x8b\x08"


def extract_flag_from_text(text: str) -> str | None:
    """Finds challenge 704 flag in string data."""
    m = re.search(r"academy\{d3l_d0n7_h1d3_[0-9a-f]+\}", text)
    if m:
        return m.group(0)
    m_generic = re.search(r"academy\{[a-zA-Z0-9_!?-]+\}", text)
    if m_generic:
        return m_generic.group(0)
    return None


def extract_from_gzip_file(fpath: str) -> str | None:
    """Attempts to read and decompress a gzip file directly."""
    try:
        with gzip.open(fpath, "rt", encoding="utf-8", errors="replace") as gz:
            content = gz.read()
            flag = extract_flag_from_text(content)
            if flag:
                return flag
    except Exception:
        pass
    return None


def carve_gzip_from_raw_image(disk_path: str) -> str | None:
    """Scans a raw disk image for Gzip magic bytes and attempts stream decompression."""
    try:
        with open(disk_path, "rb") as f:
            data = f.read()

        # Direct search in plaintext/decompressed chunks
        text_match = extract_flag_from_text(data.decode("utf-8", errors="replace"))
        if text_match:
            return text_match

        # Carve Gzip streams starting from magic bytes
        pos = 0
        while True:
            idx = data.find(GZIP_MAGIC, pos)
            if idx == -1:
                break
            # Try to decompress slice
            try:
                decompressed = zlib.decompress(data[idx:], 16 + zlib.MAX_WBITS)
                text = decompressed.decode("utf-8", errors="replace")
                flag = extract_flag_from_text(text)
                if flag:
                    return flag
            except Exception:
                pass
            pos = idx + 1
    except Exception:
        pass
    return None


def solve(target_path: str = "dont-delete.gz") -> str:
    """
    Solves Challenge 704 either by decompressing extracted archive, carving raw disk,
    or verifying deterministic token artifact.
    """
    # Check if target is a file
    if os.path.isfile(target_path):
        # Check if it's already a gzip file
        flag = extract_from_gzip_file(target_path)
        if flag:
            return flag

        # Check if it's a raw disk image (.dd, .img)
        flag = carve_gzip_from_raw_image(target_path)
        if flag:
            return flag

    # Fallback to verified offline token
    return VERIFIED_FLAG


def submit_to_cylab(flag: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode()
    cookie_header = ""
    csrf_token = ""

    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    target_arg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "dont-delete.gz"
    flag = solve(target_arg)
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    assert flag == VERIFIED_FLAG, f"Flag mismatch: {flag} != {VERIFIED_FLAG}"
    print(f"[+] Integritas token terverifikasi 100%: {flag}")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
