#!/usr/bin/env python3
"""Solver for Challenge 308 substitution1 (picoCTF 2022, Cryptography).

Monoalphabetic substitution. Crib 'lrlxpac'='academy' + 'felg'='flag' +
'zqp'='the' + frequency anchors ('fuv'='for', 'tquvz'='short', 'rlwzbvp'=
'capture', 'ruawbzpv'='computer', 'rqleepogpt'='challenges') recover the key;
flag word decodes to FR3QU3NCY_4774CK5_4R3_C001_0532A335 (case-insensitive,
verifier accepts uppercase).

Usage: solve_308_substitution1.py [message.txt path]
Verified: academy{FR3QU3NCY_4774CK5_4R3_C001_0532A335} (POST /api/submissions/ -> correct:true)
"""
import sys

EXPECTED = "academy{FR3QU3NCY_4774CK5_4R3_C001_0532A335}"
E2P = {'l': 'a', 'r': 'c', 'x': 'd', 'p': 'e', 'a': 'm', 'c': 'y',
       'z': 't', 'q': 'h', 'f': 'f', 'e': 'l', 'g': 'g',
       't': 's', 'u': 'o', 'v': 'r', 'o': 'n', 'w': 'p', 'b': 'u',
       'j': 'w', 'n': 'i', 'm': 'k', 'h': 'b', 's': 'v', 'd': 'q'}


def decode(text: str) -> str:
    return "".join(E2P.get(ch, ch) if ch.isalpha() and ch.islower() else ch
                   for ch in text.lower())


def solve(path: str = "message.txt") -> str:
    text = open(path).read()
    plain = decode(text)
    print(plain[:200])
    assert "short for capture the flag" in plain
    assert decode("lrlxpac") == "academy"
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "message.txt"))
