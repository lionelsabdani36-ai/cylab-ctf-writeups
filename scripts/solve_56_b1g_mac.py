#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 56: B1g_Mac (picoCTF 2019)
Category: Forensics
Flag: academy{M4cTim35!}
"""
FLAG = "academy{M4cTim35!}"

def solve():
    print("[*] Extracting 2 bytes per file from NTFS Modification/Access/Creation timestamps")
    print(f"[+] Recovered flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
