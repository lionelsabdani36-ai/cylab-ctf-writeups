#!/usr/bin/env python3
"""
Solver for Challenge 62: 13 (Cryptography)
Decodes ROT13 cipher string to recover the original flag.
"""
import codecs
import sys
from typing import Optional

def solve(ciphertext: Optional[str] = None) -> str:
    target = ciphertext if ciphertext else "npnqrzl{abg_gbb_onq_bs_n_ceboyrz}"
    return codecs.decode(target, "rot_13")

if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(c))
