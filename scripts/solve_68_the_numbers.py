#!/usr/bin/env python3
"""
Solver for Challenge 68: The Numbers (Cryptography)
Decodes A1Z26 substitution cipher numbers into ASCII letters:
  16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
"""
def solve():
    mapping = {
        "prefix": [16, 9, 3, 15, 3, 20, 6],
        "content": [20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1, 19, 15, 14]
    }
    p = "".join(chr(ord('a') + n - 1) for n in mapping["prefix"])
    c = "".join(chr(ord('A') + n - 1) for n in mapping["content"])
    return f"{p[:4].lower()}{p[4:].upper()}{{{c}}}"

if __name__ == "__main__":
    print("Flag:", solve())
