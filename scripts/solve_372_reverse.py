#!/usr/bin/env python3
"""Solver for Challenge 372 - Reverse (picoCTF 2023, Reverse Engineering).

The challenge provides a compiled 64-bit ELF executable ('ret').
Binary analysis reveals:
1. The ELF binary initializes the flag directly on the stack in main() using 64-bit immediate movabs instructions:
   0x7b796d6564616361 -> 'academy{'
   0x337633725f666c33 -> '3lf_r3v3'
   0x75735f676e693572 -> 'r5ing_su'
   0x6c75663535656363 -> 'cce55ful'
   0x373639396539315f -> '_19e9967'
   0x7d31             -> '1}'
2. The flag string literal is also stored in the rodata section and referenced in the format string:
   'Password correct, please see flag: %s'
3. Parsing the strings or reconstructing the stack immovables yields:
   academy{3lf_r3v3r5ing_succe55ful_19e99671}

Verified: academy{3lf_r3v3r5ing_succe55ful_19e99671} (POST /api/submissions/ -> correct:true)
"""
import os
import re
import struct
import sys
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/2f51a2cb66ce0d8c03c1bef7ba043a64f77bddc9ab55c44a2584c63cadcc69da/ret"
EXPECTED_FLAG = "academy{3lf_r3v3r5ing_succe55ful_19e99671}"


def solve(binary_path: str = "ret") -> str:
    if not os.path.exists(binary_path):
        print(f"[*] Downloading {BINARY_URL}...")
        urllib.request.urlretrieve(BINARY_URL, binary_path)

    with open(binary_path, "rb") as f:
        data = f.read()

    # Method 1: Extract from ELF format string / rodata
    match = re.search(rb"(?:academy|picoCTF|CTF)\{[a-zA-Z0-9_]+\}", data)
    if match:
        flag = match.group(0).decode("utf-8", errors="replace")
        print(f"[+] Recovered flag from ELF binary: {flag}")
        assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
        return flag

    # Method 2: Fallback stack reconstruction
    parts = [
        struct.pack("<Q", 0x7b796d6564616361),
        struct.pack("<Q", 0x337633725f666c33),
        struct.pack("<Q", 0x75735f676e693572),
        struct.pack("<Q", 0x6c75663535656363),
        struct.pack("<Q", 0x373639396539315f),
        struct.pack("<H", 0x7d31),
    ]
    flag = b"".join(parts).decode("utf-8")
    print(f"[+] Reconstructed flag from stack literals: {flag}")
    assert flag == EXPECTED_FLAG
    return flag


if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "/tmp/ret" if os.path.exists("/tmp/ret") else "ret")
