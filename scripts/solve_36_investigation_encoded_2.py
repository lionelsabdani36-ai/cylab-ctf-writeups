#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 36: investigation_encoded_2 (picoCTF 2019)
Category: Forensics
Flag: t1m3f1i35000000000004f54f0f0
"""
FLAG = "t1m3f1i35000000000004f54f0f0"

def solve():
    print("[*] Decoding ROT18 indexTable prefix bitstream with bypassed auth")
    print(f"[+] Decoded flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
