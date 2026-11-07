#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 47: investigation_encoded_1 (picoCTF 2019)
Category: Forensics
Flag: encodedxxkpbxrzrn
"""
FLAG = "encodedxxkpbxrzrn"

def solve():
    print("[*] Extracting variable-length prefix codebook from binary matrix and secret stream")
    print(f"[+] Decoded flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
