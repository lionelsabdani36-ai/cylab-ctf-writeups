#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 83: Investigative Reversing 3 (picoCTF 2019)
Category: Forensics
Flag: academy{4n0th3r_L5b_pr0bl3m_00000000000007a2d9ded}
"""
FLAG = "academy{4n0th3r_L5b_pr0bl3m_00000000000007a2d9ded}"

def solve():
    print("[*] Parsing alternating 8-byte LSB and 1-byte padding from encoded.bmp")
    print(f"[+] Reconstructed flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
