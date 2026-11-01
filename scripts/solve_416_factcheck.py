#!/usr/bin/env python3
"""Solver for Challenge 416 - FactCheck (picoCTF 2024, Reverse Engineering).

The challenge provides a 64-bit ELF binary ('bin') that dynamically constructs a flag
using std::string operations and conditional evaluations:
1. Base string initialized in [rbp-0x240]: "academy{wELF_d0N3_mate_"
2. Conditional branch 1: '5' <= 'A' (0x35 <= 0x41 is True) -> Appends "9"
3. Conditional branch 2: '6' != 'A' (0x36 != 0x41 is True) -> Appends "4"
4. Conditional branch 3: '3' - 'e' == 3 (0x33 - 0x65 == -50 != 3 is False) -> Skips "3"
5. Unconditional append: Appends "8"
6. Unconditional append: Appends "0"
7. Conditional branch 4: 'a' == 'G' (0x61 == 0x47 is False) -> Skips "a"
8. Unconditional append: Appends "e"
9. Unconditional append: Appends "1"
10. Unconditional append: Appends "e"
11. Unconditional append: Appends "2"
12. Final append: Character '}' (0x7d)
Reconstructed flag: academy{wELF_d0N3_mate_9480e1e2}

Verified: academy{wELF_d0N3_mate_9480e1e2} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import os
import subprocess
import sys
import urllib.request

BIN_URL = "https://challenge-files.cylabacademy.net/library/81b266fc3e17443b094d593e8e8e9478ebc9789125ee7d0a07e320d34119ff71/bin"
EXPECTED_FLAG = "academy{wELF_d0N3_mate_9480e1e2}"


def solve(bin_path: str = "bin") -> str:
    if not os.path.exists(bin_path):
        print(f"[*] Downloading {BIN_URL}...")
        urllib.request.urlretrieve(BIN_URL, bin_path)

    # Static extraction via emulation of disassembly logic
    base = "academy{wELF_d0N3_mate_"

    # Branch 1: '5' <= 'A' -> True -> appends '9'
    if ord('5') <= ord('A'):
        base += '9'

    # Branch 2: '6' != 'A' -> True -> appends '4'
    if ord('6') != ord('A'):
        base += '4'

    # Branch 3: '3' - 'e' == 3 -> False -> skips '3'
    if ord('3') - ord('e') == 3:
        base += '3'

    # Unconditional appends
    base += '8'
    base += '0'

    # Branch 4: 'a' == 'G' -> False -> skips 'a'
    if ord('a') == ord('G'):
        base += 'a'

    # Unconditional appends
    base += 'e'
    base += '1'
    base += 'e'
    base += '2'
    base += '}'

    print(f"[+] Reconstructed Flag: {base}")
    assert base == EXPECTED_FLAG, f"Flag mismatch: {base} vs {EXPECTED_FLAG}"
    return base


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/c416/bin" if os.path.exists("/tmp/c416/bin") else "bin"
    solve(target)
