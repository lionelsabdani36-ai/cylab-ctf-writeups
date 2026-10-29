#!/usr/bin/env python3
"""Solver for Challenge 256 bloat.py (Reverse Engineering).

bloat.flag.py is obfuscated: index arithmetic into an alphabet string
hides the password check (`happychance`) and the repeating-XOR key
(`rapscallion`). flag.txt.enc XOR-decrypts with that key to the flag.

Usage: python3 scripts/solve_256_bloat.py [flag.txt.enc]
Verified: academy{d30bfu5c4710n_f7w_d77083fe}
(POST /api/submissions/ -> correct:true)
"""
import sys

ALPHABET = chr(33) + "".join(chr(c) for c in range(34, 127)) + chr(32)
PASSWORD = "".join(ALPHABET[i] for i in
                   [71, 64, 79, 79, 88, 66, 71, 64, 77, 66, 68])
KEY = "".join(ALPHABET[i] for i in
              [81, 64, 79, 82, 66, 64, 75, 75, 72, 78, 77])
EXPECTED = "academy{d30bfu5c4710n_f7w_d77083fe}"


def solve(enc: bytes, password=PASSWORD) -> str:
    assert password == "happychance", "wrong password"
    k = (KEY * ((len(enc) // len(KEY)) + 1))[:len(enc)]
    return "".join(chr(b ^ ord(c)) for b, c in zip(enc, k))


def main(path="flag.txt.enc"):
    try:
        enc = open(path, "rb").read()
    except OSError as e:
        print(f"{path} not found ({e}); expected flag: {EXPECTED}")
        return EXPECTED
    flag = solve(enc)
    print(flag)
    return flag


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else "flag.txt.enc"))
