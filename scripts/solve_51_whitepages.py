#!/usr/bin/env python3
"""
Solver for Challenge 51: WhitePages (Forensics)
Decodes Unicode whitespace steganography (ASCII space vs EM space) into ASCII text.
"""
import urllib.request
import re

def solve(url: str = "https://challenge-files.cylabacademy.net/library/53f38374e47a48424dc7e9100aba4e4b42a590f3921cfc31188171ae7d6d61e3/whitepages.txt") -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    data = urllib.request.urlopen(req).read().decode("utf-8")
    
    # Space (0x20) -> 1, EM Space (\u2003) -> 0
    bits = ""
    for ch in data:
        if ch == "\u0020":
            bits += "1"
        elif ch == "\u2003":
            bits += "0"
            
    decoded_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte_str = bits[i:i+8]
        if len(byte_str) == 8:
            decoded_bytes.append(int(byte_str, 2))
            
    decoded_text = decoded_bytes.decode("ascii", errors="ignore")
    m = re.findall(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decoded_text)
    if m:
        return m[0]
    return "Flag not found"

if __name__ == "__main__":
    print("Flag:", solve())
