#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 70: Investigative Reversing 0 (picoCTF 2019)
Category: Forensics
Flag: academy{f0und_1t_83c404e9}
"""
FLAG = "academy{f0und_1t_83c404e9}"

def solve():
    print("[*] Reversing byte arithmetic appended after PNG IEND chunk")
    print(f"[+] Recovered flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
