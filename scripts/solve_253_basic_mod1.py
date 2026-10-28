#!/usr/bin/env python3
"""Solver for Challenge 253 basic-mod1 (picoCTF, Cryptography).

Challenge: numbers in message.txt, each mod 37 mapped to
0-25=A-Z, 26-35=0-9, 36=_. Wrap in academy{...}.

Usage: solve_253_basic_mod1.py [message.txt path or URL]
"""
import sys
import urllib.request

CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
URL = ("https://challenge-files.cylabacademy.net/library/"
       "f3895827512c6fab64095a69942e62ba9e367bb32d70ff69dc0e8fd9a826936a/message.txt")


def decode(text: str) -> str:
    nums = [int(t) for t in text.split()]
    return "academy{" + "".join(CHARSET[n % 37] for n in nums) + "}"


def main(src: str | None = None) -> str:
    if src is None:
        with urllib.request.urlopen(URL, timeout=30) as r:
            text = r.read().decode()
    elif src.startswith("http"):
        with urllib.request.urlopen(src, timeout=30) as r:
            text = r.read().decode()
    else:
        with open(src) as f:
            text = f.read()
    return decode(text)


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else None))
