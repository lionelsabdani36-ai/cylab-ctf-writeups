#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Operation Orchid (ID: 285)
Category: Forensics
Event: picoCTF 2022
Difficulty: Medium (400 pts)

Analysis & Recovery:
1. Decompress disk.flag.img.gz
2. Parse DOS partition table with Sleuthkit (mmls) -> Linux partition at offset 411648 (sector 411648)
3. Extract root history (.ash_history, inode 1875) showing:
   openssl aes256 -salt -in flag.txt -out flag.txt.enc -k unbreakablepassword1234567
4. Extract encrypted artifact flag.txt.enc (inode 1782)
5. Decrypt using OpenSSL with aes-256-cbc and sha256 message digest:
   openssl enc -d -aes-256-cbc -in flag.txt.enc -k unbreakablepassword1234567 -md sha256
"""

import os
import subprocess
import sys
import gzip
import shutil
import urllib.request
import re

IMAGE_URL = "https://challenge-files.cylabacademy.net/library/bb0cb9b59f754a578fdcff72400d49394fe4399b5bf0d34f650c5baffbad8575/disk.flag.img.gz"
PARTITION_OFFSET = 411648
ENC_INODE = 1782
PASSWORD = "unbreakablepassword1234567"

def solve(work_dir: str = "") -> str:
    if not work_dir:
        work_dir = os.path.join(os.environ.get("TMPDIR", "/home/lionelsabdani36/.hermes/cache/scratch"), "solve_285")
    os.makedirs(work_dir, exist_ok=True)

    img_gz = os.path.join(work_dir, "disk.flag.img.gz")
    img_raw = os.path.join(work_dir, "disk.flag.img")
    enc_path = os.path.join(work_dir, "flag.txt.enc")

    if not os.path.exists(img_raw):
        if not os.path.exists(img_gz):
            print(f"[*] Downloading {IMAGE_URL}...")
            urllib.request.urlretrieve(IMAGE_URL, img_gz)
        print("[*] Decompressing disk image...")
        with gzip.open(img_gz, "rb") as f_in, open(img_raw, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    print("[*] Extracting encrypted artifact via icat...")
    cmd_icat = ["icat", "-o", str(PARTITION_OFFSET), img_raw, str(ENC_INODE)]
    res = subprocess.run(cmd_icat, capture_output=True, check=True)
    with open(enc_path, "wb") as f:
        f.write(res.stdout)

    print("[*] Decrypting AES-256-CBC ciphertext...")
    cmd_dec = [
        "openssl", "enc", "-d", "-aes-256-cbc",
        "-in", enc_path,
        "-k", PASSWORD,
        "-md", "sha256"
    ]
    res_dec = subprocess.run(cmd_dec, capture_output=True)
    m = re.search(r"(?:academy|picoCTF|CTF)\{[^}]+\}", res_dec.stdout.decode("latin-1"))
    if not m:
        raise RuntimeError(f"Flag not found in decrypted output: {res_dec.stderr.decode('latin-1', 'replace')}")
    flag = m.group(0)
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"Recovered Flag: {flag}")
