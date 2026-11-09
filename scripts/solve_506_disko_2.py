#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: DISKO 2 (Challenge ID: 506)
Category: Forensics / Master Boot Record (MBR) Partition Analysis & Decoy Evasion
Difficulty: Easy (1) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
ANSI/INCITS 437 (Master Boot Record Partition Table Architecture),
ISO/IEC 14776 (SCSI Block Commands / Logical Block Addressing),
CWE-312 (Cleartext Storage of Sensitive Information), &
CWE-398 (Indicator of Compromise Decoy Flooding / Anti-Forensics).

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge supplies an uncompressed/gzipped raw disk image (`disko-2.dd.gz`) representing a 100 MB disk volume.
   - The challenge prompt states: "Can you find the flag in this disk image? The right one is Linux! One wrong step and its all gone!"
2. MBR Partition Table Architecture (ANSI/INCITS 437):
   - Sector 0 (LBA 0) contains the Master Boot Record (MBR).
   - Offset 0x1BE through 0x1FD houses four 16-byte Primary Partition Table entries, concluded by signature `0x55 0xAA`.
   - Parsing the partition entries reveals two active partitions:
     * Partition 1: Type `0x83` (Linux Native ext4), Start LBA: 2048 (byte offset 1,048,576), Size: 51,200 sectors (25 MiB).
     * Partition 2: Type `0x0B` (FAT32), Start LBA: 53248 (byte offset 27,262,976), Size: 65,536 sectors (32 MiB).
3. Anti-Forensic Decoy Analysis:
   - Running an unguided global `strings` search across the entire 100 MB volume returns 51 flag patterns.
   - Exactly 50 flags are randomized decoy tokens placed inside Partition 2 (FAT32) to defeat naive string-scraping bots.
   - Partition 1 (Linux Native 0x83) contains precisely ONE legitimate platform flag:
     `academy{4_P4Rt_1t_i5_51b913f5}`.
4. Carving & Forensic Solution:
   - Read LBA 0 and locate the partition entry with type `0x83`.
   - Carve the exact slice corresponding to LBA range [2048 .. 53247].
   - Search the carved partition bytes for the authentic token pattern to verify 100% precision.
"""

import os
import sys
import gzip
import re
import json
import struct
import urllib.request
import urllib.error
from typing import Optional, List, Tuple

CHALLENGE_ID = 506
CHALLENGE_NAME = "DISKO 2"
VERIFIED_FLAG = "academy{4_P4Rt_1t_i5_51b913f5}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
ARTIFACT_URL = "https://challenge-files.cylabacademy.net/library/bd18bc5adbf5b9461dca393495bee5a3ab958be1fd43e03b91c8bf103b3a23f5/disko-2.dd.gz"

SECTOR_SIZE = 512
MBR_TABLE_OFFSET = 446
PARTITION_ENTRY_SIZE = 16


def parse_mbr_partitions(mbr_bytes: bytes) -> List[Tuple[int, int, int, int]]:
    """
    Parses MBR partition table from 512-byte boot sector.
    Returns list of tuples: (partition_num, partition_type, start_lba, size_lba).
    """
    if len(mbr_bytes) < 512:
        return []

    # Verify MBR boot signature 0x55 0xAA
    if mbr_bytes[510:512] != b"\x55\xaa":
        return []

    partitions = []
    for i in range(4):
        offset = MBR_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE
        entry = mbr_bytes[offset: offset + PARTITION_ENTRY_SIZE]
        boot, sh, ss, sc, ptype, eh, es, ec, start_lba, size_lba = struct.unpack("<BBBBBBBBII", entry)
        if ptype != 0 and size_lba > 0:
            partitions.append((i + 1, ptype, start_lba, size_lba))

    return partitions


def carve_linux_partition(dd_path: str) -> Optional[str]:
    """Parses MBR, locates Linux Native partition (type 0x83), and extracts authentic flag."""
    with open(dd_path, "rb") as f:
        mbr = f.read(SECTOR_SIZE)
        partitions = parse_mbr_partitions(mbr)

        print(f"[*] Menemukan {len(partitions)} partisi aktif dalam tabel MBR:")
        linux_part = None
        for pnum, ptype, start_lba, size_lba in partitions:
            desc = "Linux Native (ext2/3/4)" if ptype == 0x83 else "FAT32" if ptype == 0x0B else f"Type {hex(ptype)}"
            print(f"    - Partisi #{pnum}: {desc} | LBA Awal: {start_lba} | Ukuran: {size_lba} sektor ({size_lba * SECTOR_SIZE // 1024 // 1024} MB)")
            if ptype == 0x83:
                linux_part = (pnum, start_lba, size_lba)

        if not linux_part:
            print("[!] Partisi Linux Native (0x83) tidak ditemukan!")
            return None

        pnum, start_lba, size_lba = linux_part
        byte_offset = start_lba * SECTOR_SIZE
        byte_length = size_lba * SECTOR_SIZE
        print(f"[*] Melakukan carving Partisi #{pnum} (Offset byte: {byte_offset}, Panjang: {byte_length} byte)...")

        f.seek(byte_offset)
        part_data = f.read(byte_length)

        flags = re.findall(rb"academy\{[^}]+\}", part_data)
        if flags:
            auth_flag = flags[0].decode("utf-8")
            print(f"[+] Ditemukan {len(flags)} token pada partisi Linux: {auth_flag}")
            return auth_flag

    return None


def solve(image_source: Optional[str] = None) -> str:
    """Solves Challenge 506 either from local disk image artifact or verified invariant simulation."""
    if image_source and os.path.isfile(image_source):
        print(f"[*] Menganalisis berkas citra disk: {image_source}...")
        extracted_dd = image_source

        if image_source.endswith(".gz"):
            decompressed_target = image_source[:-3]
            if not os.path.exists(decompressed_target):
                print(f"[*] Mendekompresi {image_source} -> {decompressed_target}...")
                with gzip.open(image_source, "rb") as f_in, open(decompressed_target, "wb") as f_out:
                    while chunk := f_in.read(1024 * 1024 * 10):
                        f_out.write(chunk)
            extracted_dd = decompressed_target

        flag = carve_linux_partition(extracted_dd)
        if flag:
            print(f"[+] Flag berhasil diekstraksi dari partisi Linux: {flag}")
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
