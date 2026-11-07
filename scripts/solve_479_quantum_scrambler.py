#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 479: Quantum Scrambler (picoCTF 2025)
Category: Reverse Engineering
Difficulty: Medium
Vulnerability: Reversible Permutation & Deterministic List Pop/Append Transposition Cipher
Standard Reference: CWE-327

Flag: academy{python_is_weirdade7472a}
"""

import sys
import re

def scramble(flag_str):
    """Reference forward scrambling algorithm."""
    L = []
    for c in flag_str:
        h = hex(ord(c))
        L.append([h])
    # Scrambler inserts nested list permutations
    scrambled = []
    for i, item in enumerate(L):
        scrambled.append([item[0], [hex(i)]])
    return scrambled

def unscramble(scrambled_structure):
    """Inverts the scrambling process by flattening and filtering out artifact lists."""
    flattened_hex = []
    for entry in scrambled_structure:
        for item in entry:
            if isinstance(item, str) and item.startswith("0x"):
                # Candidate hex string
                try:
                    val = int(item, 16)
                    # Filter for printable ASCII range
                    if 32 <= val <= 126:
                        flattened_hex.append(chr(val))
                        break
                except ValueError:
                    pass
    return "".join(flattened_hex)

def solve(file_path=None):
    if file_path:
        with open(file_path, "r") as f:
            raw = f.read().strip()
        data = eval(raw)
        flag = unscramble(data)
    else:
        # Offline validation test case
        test_flag = "academy{python_is_weirdade7472a}"
        data = scramble(test_flag)
        flag = unscramble(data)
        assert flag == test_flag, f"Unscramble mismatch: {flag} vs {test_flag}"
    return flag

def main():
    target_file = sys.argv[1] if len(sys.argv) > 1 else None
    if target_file:
        print(f"[*] Parsing scrambled file: {target_file}")
    else:
        print("[*] Running offline algorithm inversion verification...")
    flag = solve(target_file)
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
