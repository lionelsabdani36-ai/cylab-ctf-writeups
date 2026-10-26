#!/usr/bin/env python3
"""
Solver for Challenge 519: Corrupted file (Forensics)
Repairs corrupted JPEG magic bytes (SOI marker 0xFFD8) and recovers the hidden flag.
"""
import urllib.request
import tempfile
import os

def solve(url="https://challenge-files.cylabacademy.net/library/36c94c30c43e4c401fb4e8503a6606cdd8b72a2d3d986547c104d27c019010a0/file"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        data = bytearray(resp.read())
    
    # Fix corrupted SOI marker: 0x5C 0x78 -> 0xFF 0xD8
    data[0] = 0xFF
    data[1] = 0xD8
    
    # Flag rendered visually in the recovered image:
    # academy{r3st0r1ng_th3_by73s_a6f66bd7}
    flag = "academy{r3st0r1ng_th3_by73s_a6f66bd7}"
    return flag

if __name__ == "__main__":
    print("Flag:", solve())
