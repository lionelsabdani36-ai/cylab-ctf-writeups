#!/usr/bin/env python3
"""
Solver for Challenge 710: MultiCode (General Skills)
Decodes layered obfuscation: Base64 -> Hex -> URL-encoded -> ROT13
"""
import base64
import urllib.parse

def solve():
    raw_b64 = 'NmU3MDZlNzE3MjdhNmMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM3MzQ2ZTczMzA3MDM2MzUyNTM3NDQ='
    hex_str = base64.b64decode(raw_b64).decode().strip()
    url_enc = bytes.fromhex(hex_str).decode().strip()
    rot13_str = urllib.parse.unquote(url_enc)
    flag = ''
    for c in rot13_str:
        if 'a' <= c <= 'z':
            flag += chr((ord(c) - ord('a') - 13) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            flag += chr((ord(c) - ord('A') - 13) % 26 + ord('A'))
        else:
            flag += c
    return flag

if __name__ == '__main__':
    print('Flag:', solve())
