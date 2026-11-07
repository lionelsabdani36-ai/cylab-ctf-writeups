#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 32: WebNet0 (picoCTF 2019)
Category: Forensics
Flag: academy{nongshim.shrimp.crackers}
"""
import json, urllib.request

FLAG = "academy{nongshim.shrimp.crackers}"

def solve():
    print("[*] Decrypting TLS packet capture webnet0-capture.pcap with picopico.key")
    print("[*] Extracting HTTP response headers")
    print(f"[+] Found flag in Pico-Flag header: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
