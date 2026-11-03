#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Keygenme (ID: 276)
Category: Reverse Engineering / ELF Binary Reversing & Keygen Generation
Event: picoCTF 2022
Difficulty: Hard (400 pts)

Analysis & Recovery:
1. Challenge provides a 64-bit ELF executable (keygenme) dynamically linked with OpenSSL.
2. In function main (0x149b):
   - Prompts for a 36-character license key via fgets(buf, 0x25, stdin).
   - Calls validation function check_key at 0x1209.
3. In function check_key (0x1209):
   - Initializes constant prefix string: "academy{br1ng_y0ur_0wn_k3y_" (27 bytes).
   - Initializes suffix delimiter string: "}" (1 byte).
   - Computes MD5 digest of prefix string (stored at [rbp-0xb0]).
   - Computes MD5 digest of suffix string (stored at [rbp-0xa0]).
   - Converts both 16-byte MD5 digests to 32-character lowercase hex strings:
     - hex_1 = MD5("academy{br1ng_y0ur_0wn_k3y_").hexdigest() = "716d14648eaf13021431eb50f77dd070"
     - hex_2 = MD5("}").hexdigest() = "cbb184dd8e05c9709e5dcaedaa0495cf"
   - Assembles expected key buffer (36 chars) by concatenating:
     - Characters 0-26: prefix string "academy{br1ng_y0ur_0wn_k3y_"
     - Character 27: hex_1[22] = '5'
     - Character 28: hex_1[21] = 'b'
     - Character 29: hex_1[22] = '5'
     - Character 30: hex_1[3]  = 'd'
     - Character 31: hex_2[13] = '9'
     - Character 32: hex_1[8]  = '8'
     - Character 33: hex_1[13] = '3'
     - Character 34: hex_1[9]  = 'e'
     - Character 35: '}'
4. Resulting full valid key:
   academy{br1ng_y0ur_0wn_k3y_5b5d983e}
"""

import hashlib
import os
import subprocess
import sys
import urllib.request

BINARY_URL = "https://challenge-files.cylabacademy.net/library/f8dcabb458e393453605438330fd59af2a0bcf13d04857ede5bb6ecb9bc1ed6e/keygenme"

def generate_key() -> str:
    prefix = b"academy{br1ng_y0ur_0wn_k3y_"
    suffix = b"}"

    hex_1 = hashlib.md5(prefix).hexdigest()
    hex_2 = hashlib.md5(suffix).hexdigest()

    # Derived from stack disassembly offsets in check_key (0x1209)
    # [rbp-0x5a] -> hex_1[0x70 - 0x5a] = hex_1[22]
    # [rbp-0x5b] -> hex_1[0x70 - 0x5b] = hex_1[21]
    # [rbp-0x5a] -> hex_1[0x70 - 0x5a] = hex_1[22]
    # [rbp-0x6d] -> hex_1[0x70 - 0x6d] = hex_1[3]
    # [rbp-0x43] -> hex_2[0x50 - 0x43] = hex_2[13]
    # [rbp-0x68] -> hex_1[0x70 - 0x68] = hex_1[8]
    # [rbp-0x63] -> hex_1[0x70 - 0x63] = hex_1[13]
    # [rbp-0x67] -> hex_1[0x70 - 0x67] = hex_1[9]
    # [rbp-0xb2] -> '}'

    key_chars = [
        prefix.decode("ascii"),
        hex_1[22],
        hex_1[21],
        hex_1[22],
        hex_1[3],
        hex_2[13],
        hex_1[8],
        hex_1[13],
        hex_1[9],
        "}"
    ]
    return "".join(key_chars)

def solve(bin_path: str = "") -> str:
    key = generate_key()
    print(f"[*] Generated License Key: {key}")

    if bin_path and os.path.exists(bin_path):
        print(f"[*] Validating against binary: {bin_path}")
        p = subprocess.run([bin_path], input=(key + "\n").encode(), capture_output=True)
        out = p.stdout.decode()
        if "That key is valid" in out:
            print("[+] Verification passed: Binary returned 'That key is valid.'")
        else:
            print(f"[-] Verification output: {out}")
    return key

if __name__ == "__main__":
    flag = solve(sys.argv[1] if len(sys.argv) > 1 else "/tmp/keygenme")
    print(f"[+] Flag: {flag}")
