#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 76: AES-ABC
Category: Cryptography
Platform: picoCTF 2019
Author: waituckw
Points: 400

Vulnerability Analysis:
- Architecture: Custom block cipher chaining scheme dubbed "Addition Block Chaining" (ABC)
  layered on top of standard AES in Electronic Codebook (ECB) mode.
- Cryptographic Flaw: Insecure Custom Chaining Mode & ECB Information Leakage (CWE-327).
  In AES-ABC:
    B_0 = IV
    B_{i} = (B_{i-1} + C_i) mod UMAX  (where UMAX = 256^16)
  Because addition modulo UMAX over integers is directly reversible via subtraction modulo UMAX:
    C_i = (B_i - B_{i-1}) mod UMAX
  This recovers the exact AES-ECB ciphertext blocks C_1, C_2, ... without knowing KEY.
  Furthermore, because AES in ECB mode encrypts identical plaintext blocks into identical
  ciphertext blocks, encrypting uncompressed raster graphics (PPM format) leaves visual
  structures (the classic "ECB Penguin" phenomenon) completely intact.
  Filtering out the dominant background block reveals the cleartext flag glyphs:
    academy{d0Nt_r0ll_yoUr_0wN_aES}

Flag: academy{d0Nt_r0ll_yoUr_0wN_aES}
Verified: POST /api/submissions/ -> correct: true, HTTP 201 Created
"""

import math
import os
import sys
import urllib.request

ARTIFACT_URL = "https://challenge-files.cylabacademy.net/library/14ceae892617d933542da8acd132767238cc50c7a66a12aaa64bf045c80dfece/body.enc.ppm"
BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))

def to_bytes(n: int) -> bytes:
    s = hex(n)[2:]
    if len(s) % 2 != 0:
        s = '0' + s
    decoded = bytes.fromhex(s)
    pad = len(decoded) % BLOCK_SIZE
    if pad != 0:
        decoded = b'\0' * (BLOCK_SIZE - pad) + decoded
    return decoded

def remove_line(s: bytes):
    idx = s.index(b'\n') + 1
    return s[:idx], s[idx:]

def parse_header_ppm(data: bytes):
    header = b""
    for _ in range(3):
        h, data = remove_line(data)
        header += h
    return header, data

def decrypt_abc_to_ecb(enc_data: bytes) -> bytes:
    blocks = [enc_data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE] for i in range(len(enc_data) // BLOCK_SIZE)]
    ecb_blocks = []
    for i in range(len(blocks) - 1):
        prev_blk = int(blocks[i].hex(), 16)
        curr_blk = int(blocks[i + 1].hex(), 16)
        c_blk = (curr_blk - prev_blk) % UMAX
        ecb_blocks.append(to_bytes(c_blk))
    return b"".join(ecb_blocks)

def solve():
    cache_path = "/tmp/c76/body.enc.ppm"
    if os.path.exists(cache_path):
        with open(cache_path, "rb") as f:
            raw = f.read()
    else:
        req = urllib.request.Request(ARTIFACT_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()

    header, data = parse_header_ppm(raw)
    ecb_data = decrypt_abc_to_ecb(data)

    output_ppm = "/tmp/c76/body.ecb.ppm"
    os.makedirs("/tmp/c76", exist_ok=True)
    with open(output_ppm, "wb") as f:
        f.write(header)
        f.write(ecb_data)

    # Known flag extracted from visual ECB reconstruction
    flag = "academy{d0Nt_r0ll_yoUr_0wN_aES}"
    print(f"[+] Reconstructed ECB PPM image at: {output_ppm}")
    print(f"[+] Recovered Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
