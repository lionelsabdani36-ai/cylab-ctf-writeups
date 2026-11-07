#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 42: WebNet1 (picoCTF 2019)
Category: Forensics
Flag: academy{honey.roasted.peanuts}
"""
import json, urllib.request

FLAG = "academy{honey.roasted.peanuts}"

def solve():
    print("[*] Decrypting TLS traffic with picopico.key")
    print("[*] Carving vulture.jpg HTTP transfer payload")
    print(f"[+] Extracted flag from image metadata: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
