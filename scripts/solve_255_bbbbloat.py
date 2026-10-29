#!/usr/bin/env python3
"""Solver for Challenge 255 Bbbbloat (Reverse Engineering).

Stripped PIE binary asks "What's my favorite number?". Static analysis
(GDB disassembly) shows the accepted value is compared against 0x86187
(549255); on match it decodes an obfuscated stack string with the
transform: for each byte c (0x20 < c != 0x7f): c = c + 0x2f, wrapping
values above 0x7e back by 0x5e. The embedded blob
  24256>JL4Ff0f9b03=_cf0`47b2cg`N
decodes to the flag. No execution needed (chmod+exec is blocked on
headless runners); pure emulation below.

Usage: python3 scripts/solve_255_bbbbloat.py
Verified: academy{cu7_7h3_bl047_1cf3a481}
(POST /api/submissions/ -> correct:true)
"""
import struct

BLOB = struct.pack("<4Q", 0x4C4A3E3635323432, 0x3062396630664634,
                   0x34603066635F3D33, 0x4E606763326237)
FAVORITE = 0x86187  # 549255
EXPECTED = "academy{cu7_7h3_bl047_1cf3a481}"


def transform(data: bytes) -> str:
    out = []
    for ch in data.decode():
        o = ord(ch)
        if o <= 0x20 or o == 0x7f:
            out.append(ch)
            continue
        v = o + 0x2F
        out.append(chr(v - 0x5E) if v > 0x7E else chr(v))
    return "".join(out).rstrip("\x00")


def solve() -> str:
    print(f"favorite number: {FAVORITE}")
    flag = transform(BLOB)
    print(flag)
    return flag


if __name__ == "__main__":
    print(solve())
