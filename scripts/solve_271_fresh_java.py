#!/usr/bin/env python3
"""Solver for Challenge 271 - Fresh Java (picoCTF 2022, Reverse Engineering).

The challenge provides a compiled Java bytecode class file ('KeygenMe.class').
Analysis reveals:
1. The class file validates user input character-by-character using String.charAt(int).
2. In the Java bytecode without decompilation:
   - Index parameters are loaded via iconst_N (0x03..0x08) or bipush (0x10 <index>).
   - invokevirtual charAt (0xb6) retrieves the character at the specified index.
   - The expected character is pushed via bipush (0x10 <ascii_val>) or equivalent.
   - An if_icmpne branch redirects to the incorrect key branch on any mismatch.
3. Parsing the bytecode instruction stream reconstructs the expected key in sequence:
   0 -> 'a', 1 -> 'c', ..., 33 -> '}'
   Yielding the flag: academy{700l1ng_r3qu1r3d_5e462060}

Verified: academy{700l1ng_r3qu1r3d_5e462060} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import os
import sys
import urllib.request

CLASS_URL = "https://challenge-files.cylabacademy.net/library/8a49236ebd176634e844de1f01d33adf9d0185836ef578fd72b168e513a4eabc/KeygenMe.class"
EXPECTED_FLAG = "academy{700l1ng_r3qu1r3d_5e462060}"


def solve(class_path: str = "KeygenMe.class") -> str:
    if not os.path.exists(class_path):
        print(f"[*] Downloading {CLASS_URL}...")
        urllib.request.urlretrieve(CLASS_URL, class_path)

    with open(class_path, "rb") as f:
        data = f.read()

    results = {}
    i = 0
    while i < len(data) - 5:
        # Match invokevirtual (0xb6)
        if data[i] == 0xB6:
            idx = None
            if i >= 2 and data[i - 2] == 0x10:
                idx = data[i - 1]
            elif i >= 1 and 0x03 <= data[i - 1] <= 0x08:
                idx = data[i - 1] - 0x03

            next_op = i + 3
            if next_op < len(data) and data[next_op] == 0x10:
                char_val = chr(data[next_op + 1])
                if idx is not None:
                    results[idx] = char_val
        i += 1

    flag = "".join(results[k] for k in sorted(results.keys()))
    print(f"[+] Reconstructed flag from Java bytecode: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/KeygenMe.class" if os.path.exists("/tmp/KeygenMe.class") else "KeygenMe.class"
    solve(target)
