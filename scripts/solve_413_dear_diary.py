#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Dear Diary (ID: 413)
Category: Forensics / Filesystem Metadata Carving & Directory Entry Reconstruction
Event: picoCTF 2024
Difficulty: Medium (400 pts)

Analysis & Recovery:
1. Decompress disk.flag.img.gz.
2. In ext4 partition, directory /root/secret-secrets contains files:
   - force-wait.sh
   - innocuous-file.txt
   - its-all-in-the-name
3. The file innocuous-file.txt was repeatedly created, written to with small name fragments,
   and unlinked. Directory entry (dirent) structures across the filesystem retain deleted
   entry metadata where file names contain fragments of the flag.
4. Parsing all dirent records associated with the inode or following innocuous-file.txt
   reveals the sequence: pic, oCT, F{1, _53, 3_n, 4m3, 5_a, 1ee, d51, 7} -> 1_533_n4m35_a1eed517.
5. In CyLab Security Academy, platform flag is normalized to academy{1_533_n4m35_a1eed517}.
"""

import gzip
import os
import re
import shutil
import struct
import urllib.request

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/a25bb84ce58309d7ba5cfe01dd4d6d2ce05e5d4cfd5307216cec07d1eab3267c/disk.flag.img.gz"

def solve(image_path: str = "") -> str:
    if not image_path:
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_413")
        os.makedirs(work_dir, exist_ok=True)
        image_path = os.path.join(work_dir, "disk.flag.img")
        gz_path = os.path.join(work_dir, "disk.flag.img.gz")
        if not os.path.exists(image_path):
            if not os.path.exists(gz_path):
                print(f"[*] Downloading {IMAGE_URL}...")
                urllib.request.urlretrieve(IMAGE_URL, gz_path)
            print("[*] Decompressing disk image...")
            with gzip.open(gz_path, "rb") as f_in, open(image_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

    print("[*] Scanning disk image for dirent patterns associated with innocuous-file.txt...")
    with open(image_path, "rb") as f:
        data = f.read()

    # Find dirent structures around 'innocuous-file.txt'
    # Ext4 directory entry format:
    # inode (4 bytes), rec_len (2 bytes), name_len (1 byte), file_type (1 byte), name
    # The subsequent dirent in the directory block contains the fragmented name
    matches = [m.start() for m in re.finditer(b"innocuous-file.txt", data)]
    fragments = []

    for offset in matches:
        chunk = data[offset : offset + 120]
        # Inode 1845 (0x0735 little endian: b'\x35\x07\x00\x00')
        idx = chunk.find(b"\x35\x07\x00\x00")
        if idx != -1:
            entry = chunk[idx:]
            if len(entry) >= 8:
                name_len = entry[6]
                name = entry[8 : 8 + name_len].decode("latin-1", "replace")
                if name not in ("its-all-in-the-name", "original-filename") and name not in fragments:
                    fragments.append(name)

    print(f"[*] Extracted fragments: {fragments}")
    combined = "".join(fragments)
    m_flag = re.search(r"\{([^}]+)\}", combined)
    if m_flag:
        inner = m_flag.group(1)
    else:
        inner = combined

    flag = f"academy{{{inner}}}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"Recovered Flag: {flag}")
