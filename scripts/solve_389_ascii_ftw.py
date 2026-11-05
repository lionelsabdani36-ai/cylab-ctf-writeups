#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 389: ASCII FTW (picoCTF 2023)
Category: Reverse Engineering / Stack Byte Reconstruction & Hex-ASCII Conversion
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Static Binary Disassembly & Stack Byte Recovery)

Description:
This program has constructed the flag using hex ascii values. Identify the flag
text by disassembling the program.

Disassembly of main:
c6 45 d0 61          mov    BYTE PTR [rbp-0x30],0x61
c6 45 d1 63          mov    BYTE PTR [rbp-0x2f],0x63
...
c6 45 ee 7d          mov    BYTE PTR [rbp-0x12],0x7d

Analysis:
The main function initializes a character buffer on the stack one byte at a time
using immediate hex constants:
0x61, 0x63, 0x61, 0x64, 0x65, 0x6d, 0x79, 0x7b, ...
Translating each hexadecimal byte to its ASCII representation yields:
academy{ASCII_IS_EASY_AC3E0C8C}
Flag: academy{ASCII_IS_EASY_AC3E0C8C}
"""

import os
import re
import subprocess
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/60ac124e46a3c8894d62ac83ba929cdebd78f28658dc91611d4aae76ad1cb41a/asciiftw"
EXPECTED_FLAG = "academy{ASCII_IS_EASY_AC3E0C8C}"

def solve(binary_path: str | None = None) -> str:
    # If binary path is not given, check local cache or download
    if binary_path is None or not os.path.exists(binary_path):
        cached_path = "/home/lionelsabdani36/.hermes/cache/scratch/batch63/asciiftw"
        if os.path.exists(cached_path):
            binary_path = cached_path
        else:
            scratch_dir = "/home/lionelsabdani36/.hermes/cache/scratch/batch63"
            os.makedirs(scratch_dir, exist_ok=True)
            binary_path = os.path.join(scratch_dir, "asciiftw")
            req = urllib.request.Request(BINARY_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                with open(binary_path, "wb") as f:
                    f.write(resp.read())
            os.chmod(binary_path, 0o755)

    assert os.path.exists(binary_path)

    # Disassemble binary using objdump
    res = subprocess.run(["objdump", "-d", "-M", "intel", binary_path], capture_output=True, text=True, check=True)
    out = res.stdout

    # Find sequence of mov BYTE PTR [rbp-0x...], 0x...
    matches = re.findall(r"mov\s+BYTE PTR\s+\[rbp-0x([0-9a-fA-F]+)\],\s*(0x[0-9a-fA-F]+)", out)
    if not matches:
        raise ValueError("Could not find byte moves into stack buffer")

    # Sort matches by offset descending (from 0x30 down to 0x12)
    parsed = []
    for offset_hex, val_hex in matches:
        offset = int(offset_hex, 16)
        val = int(val_hex, 16)
        parsed.append((offset, val))

    # Higher offset means lower memory address on stack (rbp - offset)
    parsed.sort(key=lambda x: -x[0])

    flag_bytes = bytes([val for _, val in parsed])
    flag = flag_bytes.decode("ascii", errors="replace")

    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered Flag: {flag}")
