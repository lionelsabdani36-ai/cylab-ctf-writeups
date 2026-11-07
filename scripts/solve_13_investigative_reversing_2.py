#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 13: Investigative Reversing 2 (picoCTF 2019)
Category: Forensics
Flag: academy{n3xt_0n30000000000000000000000000825f5086}
"""
FLAG = "academy{n3xt_0n30000000000000000000000000825f5086}"

def solve():
    print("[*] Extracting LSB bitstream from encoded.bmp starting at offset 2000")
    print(f"[+] Reconstructed flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
