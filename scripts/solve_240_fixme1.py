#!/usr/bin/env python3
"""
Solver for Challenge 240: fixme1.py (CyLab Security Academy / picoCTF)
Fixes unexpected indentation error in python script.
"""
def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

flag_enc = chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) + chr(0x1c) + chr(0x15) + chr(0x5a) + chr(0x07) + chr(0x00) + chr(0x46) + chr(0x0b) + chr(0x1a) + chr(0x5a) + chr(0x1d) + chr(0x1d) + chr(0x2a) + chr(0x06) + chr(0x1c) + chr(0x5a) + chr(0x5c) + chr(0x55) + chr(0x40) + chr(0x3a) + chr(0x08) + chr(0x5d) + chr(0x5a) + chr(0x53) + chr(0x40) + chr(0x52) + chr(0x0f) + chr(0x0f) + chr(0x14)

flag = str_xor(flag_enc, 'enkidu')
print("Flag:", flag)
