#!/usr/bin/env python3
"""
Solver for Challenge 251: Serpentine (General Skills)
Decodes the encrypted flag using the embedded XOR algorithm in serpentine.py.
"""
import sys

def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(s) ^ ord(k)) for (s, k) in zip(secret, new_key)])

def solve() -> str:
    flag_enc = (
        chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) +
        chr(0x1c) + chr(0x15) + chr(0x5c) + chr(0x01) + chr(0x57) + chr(0x2a) +
        chr(0x17) + chr(0x5e) + chr(0x5f) + chr(0x0d) + chr(0x3b) + chr(0x19) +
        chr(0x56) + chr(0x5b) + chr(0x5e) + chr(0x36) + chr(0x53) + chr(0x07) +
        chr(0x51) + chr(0x18) + chr(0x58) + chr(0x05) + chr(0x57) + chr(0x11) +
        chr(0x3a) + chr(0x56) + chr(0x59) + chr(0x5c) + chr(0x06) + chr(0x44) +
        chr(0x55) + chr(0x0f) + chr(0x0e) + chr(0x14)
    )
    return str_xor(flag_enc, "enkidu")

if __name__ == "__main__":
    print("Flag:", solve())
