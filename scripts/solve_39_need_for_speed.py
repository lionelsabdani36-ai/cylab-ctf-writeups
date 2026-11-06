#!/usr/bin/env python3
"""
Reproducible Solver for CyLab Challenge ID 39: Need For Speed (picoCTF 2019)
Category: Reverse Engineering
Author: Alexander Bushkin
Points: 400

Technical Analysis:
1. Binary sets a 1-second SIGALRM timer (set_timer) that invokes alarm_handler, terminating the process.
2. An intentional CPU-intensive busy loop in calculate_key decrements an integer over multiple cycles,
   stopping at 0xdaf852c0. Because the loop execution exceeds 1 second, SIGALRM fires before completion.
3. The key is deterministically 0xdaf852c0. The flag decryption routine applies a rolling XOR keystream
   against the encrypted buffer in .data (file offset 0x3020) and increments the key every 3 bytes.
4. This script downloads the binary artifact from CyLab CDN (if not cached locally) and emulates
   the flag decryption algorithm statically, bypassing the alarm restriction.
"""

import os
import sys
import urllib.request
import re

CDN_URL = "https://challenge-files.cylabacademy.net/library/d7c68ebb2e1f0e5d03ceb028848a0d7a93a6519bb0296147ad9f4e9f60178b1b/need-for-speed"
LOCAL_BIN = os.path.join(os.path.dirname(__file__), "need-for-speed")

def get_binary_bytes():
    # Check scratch or local path
    possible_paths = [
        LOCAL_BIN,
        "/home/lionelsabdani36/.hermes/cache/scratch/chall_39/need-for-speed"
    ]
    for p in possible_paths:
        if os.path.exists(p):
            with open(p, "rb") as f:
                return f.read()

    print(f"[*] Downloading artifact from {CDN_URL}...")
    req = urllib.request.Request(CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        return resp.read()

def decrypt_flag_buffer(binary_bytes):
    # .data section is at file offset 0x3000, encrypted flag buffer at 0x3020
    offset = 0x3020
    enc = binary_bytes[offset:offset + 56]
    key = 0xdaf852c0
    dec = bytearray(enc)

    for i in range(len(dec)):
        k_bytes = key.to_bytes(4, "little")
        k_byte = k_bytes[i % 2]
        dec[i] ^= k_byte
        if (i % 3) == 2:
            key = (key + 1) & 0xffffffff

    match = re.search(r"academy\{[^}]+\}", dec.decode(errors="ignore"))
    if match:
        return match.group(0)
    return dec.split(b"\x00")[0].decode(errors="ignore")

def main():
    print("[*] CyLab Challenge ID 39: Need For Speed Solver")
    bin_data = get_binary_bytes()
    flag = decrypt_flag_buffer(bin_data)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
