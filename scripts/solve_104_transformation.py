#!/usr/bin/env python3
"""
Solver for Challenge 104: Transformation (Reverse Engineering)
Reverses 16-bit big-endian character packing:
  chr((ord(c1) << 8) + ord(c2))
"""
import os

def solve(enc_path="enc"):
    with open(enc_path, "r", encoding="utf-8") as f:
        enc = f.read().strip()
    flag = ""
    for c in enc:
        val = ord(c)
        flag += chr(val >> 8) + chr(val & 0xFF)
    return flag

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/104/enc"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{16_bits_inst34d_of_8_790ba37e}")
