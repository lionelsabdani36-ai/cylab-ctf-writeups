#!/usr/bin/env python3
"""Solver for Challenge 287 patchme.py (picoCTF 2022, Reverse Engineering).

Vuln: password hard-coded as 4 concatenated literals
("ak98"+"-=90"+"adfjhgj321"+"sleuth9000"); flag.txt.enc decrypted with
repeating-key XOR key "utilitarian" via str_xor().

Usage: solve_287_patchme.py [patchme.flag.py dir]
Verified: academy{p47ch1ng_l1f3_h4ck_a68602e7} (POST /api/submissions/ -> correct:true)
"""
import os
import sys

EXPECTED = "academy{p47ch1ng_l1f3_h4ck_a68602e7}"
PASSWORD = "ak98" + "-=90" + "adfjhgj321" + "sleuth9000"
KEY = "utilitarian"


def str_xor(secret: bytes, key: str) -> str:
    nk = (key * ((len(secret) // len(key)) + 1))[:len(secret)]
    return "".join(chr(b ^ ord(k)) for b, k in zip(secret, nk))


def solve(base: str = ".") -> str:
    assert PASSWORD == "ak98-=90adfjhgj321sleuth9000"
    with open(os.path.join(base, "flag.txt.enc"), "rb") as f:
        enc = f.read()
    flag = str_xor(enc, KEY)
    print(flag)
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "."))
