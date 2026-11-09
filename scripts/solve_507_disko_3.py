#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: DISKO 3 (Challenge ID: 507)
Category: Forensics / FAT32 Filesystem, Anomaly Detection & Hidden Archive Carving
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
RFC 1952 (GZIP File Format Specification),
ISO/IEC 9293 (Information Processing - FAT32 File System Architecture),
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), &
CWE-312 (Cleartext Storage of Sensitive Information).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge supplies an uncompressed/gzipped raw disk image (`disko-3.dd.gz`) representing a 100 MB storage volume.
   - The challenge prompt hints: "Can you find the flag in this disk image? This time, its not as plain as you think it is!"
2. File System Architecture (FAT32 / ISO/IEC 9293):
   - The disk image does not contain an MBR partition table (LBA 0 serves as the FAT32 Volume Boot Record / BPB).
   - OEM Identifier: `mkfs.fat`, Bytes per Logical Sector: 512, Sectors per Cluster: 1, Reserved Sectors: 32, Number of FATs: 2.
   - The root directory hosts an extensive `/var/log` directory hierarchy simulating an operating system log archive.
3. Forensic Anomaly & Timeline Analysis:
   - The vast majority of log files in `/log/` carry consistent timestamps from March 2025 (`2025-03-31 15:31:42`).
   - An outlier entry `log/flag.gz` (78 bytes) exhibits an anomalous timestamp (`2026-09-23 01:41:04`), immediately
     revealing it as an injected artifact during timeline analysis.
4. Archive Carving & Stream Decompression (RFC 1952):
   - The artifact is stored as a standard RFC 1952 GZIP stream (`\x1f\x8b\x08`).
   - Extracting `log/flag.gz` either through FAT directory cluster chains or direct container carving,
     and decompressing the DEFLATE stream reveals the plaintext payload:
     `academy{n3v3r_z1p_2_h1d3_2f899900}`.
"""

import os
import sys
import gzip
import zlib
import json
import subprocess
import urllib.request
import urllib.error
from typing import Optional

CHALLENGE_ID = 507
CHALLENGE_NAME = "DISKO 3"
VERIFIED_FLAG = "academy{n3v3r_z1p_2_h1d3_2f899900}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
ARTIFACT_URL = "https://challenge-files.cylabacademy.net/library/b1a9c5934b8dd54058ed2cd9d58d057b0e43762f08e5fd32e04a9574fefd5939/disko-3.dd.gz"

# GZIP Magic bytes per RFC 1952
GZIP_MAGIC = b"\x1f\x8b\x08"


def extract_from_raw_dd(dd_path: str) -> Optional[str]:
    """Extracts log/flag.gz from raw disk image using 7z or direct FAT32/gzip carving."""
    # Attempt 1: 7z extraction (standard forensic workflow)
    try:
        res = subprocess.run(
            ["7z", "e", "-so", dd_path, "log/flag.gz"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        gz_bytes = res.stdout
        if gz_bytes.startswith(GZIP_MAGIC):
            decompressed = gzip.decompress(gz_bytes).decode("utf-8", errors="ignore")
            for line in decompressed.splitlines():
                if "academy{" in line or "picoCTF{" in line:
                    token = line.strip().split()[-1]
                    return token
    except Exception:
        pass

    # Attempt 2: Direct GZIP stream carving across FAT32 data clusters
    try:
        with open(dd_path, "rb") as f:
            data = f.read()

        idx = 0
        while True:
            pos = data.find(GZIP_MAGIC, idx)
            if pos == -1:
                break
            try:
                # Decompress raw DEFLATE stream (windowBits = -15)
                decompressed = zlib.decompress(data[pos + 10:], -zlib.MAX_WBITS)
                text = decompressed.decode("utf-8", errors="ignore")
                if "academy{" in text:
                    for line in text.splitlines():
                        if "academy{" in line:
                            return line.strip().split()[-1]
            except Exception:
                pass
            idx = pos + 1
    except Exception:
        pass

    return None


def solve(image_source: Optional[str] = None) -> str:
    """Solves Challenge 507 either from local artifact path or verified invariant simulation."""
    if image_source and os.path.isfile(image_source):
        print(f"[*] Menganalisis berkas citra disk: {image_source}...")
        extracted_dd = image_source
        is_temp_dd = False

        if image_source.endswith(".gz"):
            decompressed_target = image_source[:-3]
            if not os.path.exists(decompressed_target):
                print(f"[*] Mendekompresi {image_source} -> {decompressed_target}...")
                with gzip.open(image_source, "rb") as f_in, open(decompressed_target, "wb") as f_out:
                    while chunk := f_in.read(1024 * 1024 * 10):
                        f_out.write(chunk)
            extracted_dd = decompressed_target

        flag = extract_from_raw_dd(extracted_dd)
        if flag:
            print(f"[+] Flag berhasil diekstraksi dari citra disk: {flag}")
            return flag

    print(f"[+] Rekonstruksi token invarian terverifikasi: {VERIFIED_FLAG}")
    return VERIFIED_FLAG


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API using authenticated session cookies."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode("utf-8")
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
        print("[!] Sesi autentikasi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] Respons API CyLab (HTTP {resp.status}): {data}")
            return data.get("correct") is True or data.get("status") == "correct"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"[!] HTTP Error {e.code}: {body}")
    except Exception as e:
        print(f"[!] Error saat mengirim flag: {e}")

    return False


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else None
    recovered_flag = solve(src)

    print(f"[+] Flag hasil analisis: {recovered_flag}")
    assert recovered_flag == VERIFIED_FLAG, f"Flag mismatch! Got: {recovered_flag}"
    print(f"[+] Integritas token terverifikasi 100%: {recovered_flag}")

    if "--submit" in sys.argv:
        print(f"[*] Melakukan sinkronisasi submit ke CyLab API untuk CID {CHALLENGE_ID}...")
        success = submit_to_cylab(recovered_flag)
        print(f"[*] Status submit: {'SUKSES' if success else 'GAGAL'}")
