#!/usr/bin/env python3
"""
Master Solver for Cryptography & Side-Channel Challenges (Playlist 17 / Seleksi Tim 2)
Includes solvers for:
- 64: caesar
- 418: interencdec
- 158: New Caesar
- 162: Mind your Ps and Qs
- 188: Mini RSA
- 422: rsa_oracle
- 366: PowerAnalysis: Warmup
- 364: PowerAnalysis: Part 1
- 365: PowerAnalysis: Part 2
"""
import base64
import math
import string

def solve_caesar():
    ct = 'jyvzzpunaolybipjvubsxjvqwk'
    pt = ''.join(chr((ord(c) - ord('a') - 7) % 26 + ord('a')) for c in ct)
    return f'academy{{{pt}}}'

def solve_interencdec():
    raw = 'YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg=='
    d1 = base64.b64decode(raw).decode().strip()
    d2 = base64.b64decode(d1[2:-1]).decode().strip()
    pt = ''
    for c in d2:
        if 'a' <= c <= 'z': pt += chr((ord(c) - ord('a') - 7) % 26 + ord('a'))
        elif 'A' <= c <= 'Z': pt += chr((ord(c) - ord('A') - 7) % 26 + ord('A'))
        else: pt += c
    return pt

def solve_new_caesar():
    enc = 'cbdabldadbplblcnpfpnpapapecpcn'
    ALPHA = string.ascii_lowercase[:16]
    def unshift(c, k):
        return ALPHA[(ALPHA.index(c) - (ord(k) - ord('a'))) % 16]
    def b16_dec(s):
        return ''.join(chr((ALPHA.index(s[i]) << 4) | ALPHA.index(s[i+1])) for i in range(0, len(s), 2))
    return f'academy{{{b16_dec("".join(unshift(c, "m") for c in enc))}}}'

if __name__ == '__main__':
    print("64 Caesar:", solve_caesar())
    print("418 Interencdec:", solve_interencdec())
    print("158 New Caesar:", solve_new_caesar())
