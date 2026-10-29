#!/usr/bin/env python3
"""Solver for Challenge 313 unpackme (picoCTF 2022, Reverse Engineering).

UPX-packed ELF64. Unpack with `upx -d`, then: main asks "What's my favorite
number?" and compares scanf'd int against 0xb83cb (754635). On match it calls
rotate_encrypt on the embedded string and prints the flag.

Usage: solve_313_unpackme.py [unpacked-binary path]
Verified: academy{up><_m3_f7w_a6924bf9} (POST /api/submissions/ -> correct:true)
"""
import subprocess
import sys

EXPECTED = "academy{up><_m3_f7w_a6924bf9}"


def solve(path: str = "unpackme-upx-unpacked") -> str:
    out = subprocess.run([path], input="754635\n", capture_output=True,
                         text=True, timeout=15).stdout
    import re
    m = re.search(r"academy\{[^}]*\}", out)
    assert m, "no flag in program output: %r" % out
    flag = m.group(0)
    print(out.strip())
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "unpackme-upx-unpacked"))
