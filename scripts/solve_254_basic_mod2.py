#!/usr/bin/env python3
"""Solver for Challenge 254 basic-mod2 (picoCTF, Cryptography).

Challenge: numbers in message.txt; take each mod 41, compute the modular
inverse, map 1-26=A-Z, 27-36=0-9, 37=_. Wrap in academy{...}.

Usage: solve_254_basic_mod2.py [message.txt path or URL]
"""
import sys
import urllib.request

CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
URL = ("https://challenge-files.cylabacademy.net/library/"
       "4f25bc41d739375d13732691063a72f372cc433988ff76ad620c458a792b5c9e/message.txt")


def decode(text: str) -> str:
    out = []
    for tok in text.split():
        inv = pow(int(tok) % 41, -1, 41)
        if not 1 <= inv <= 37:
            raise ValueError(f"inverse out of range: {tok} -> {inv}")
        out.append(CHARSET[inv - 1])
    return "academy{" + "".join(out) + "}"


def main(src: str | None = None) -> str:
    if src is None or src.startswith("http"):
        with urllib.request.urlopen(src or URL, timeout=30) as r:
            text = r.read().decode()
    else:
        with open(src) as f:
            text = f.read()
    return decode(text)


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else None))
