#!/usr/bin/env python3
"""Solver for Challenge 309 substitution2 (picoCTF 2022, Cryptography).

Monoalphabetic substitution, no spaces/punctuation (1288 chars). Solved with
quadgram hill-climbing (simulated annealing, War-and-Peace reference text).
Plaintext is prose about high-school security competitions, ending with:
'machines the flag is academy{n6r4m_4n41y515_15_73d10u5_fd56c357}'.
Digits/underscores pass through unchanged.

Usage: solve_309_substitution2.py [message.txt path]
Verified: academy{N6R4M_4N41Y515_15_73D10U5_FD56C357} (POST /api/submissions/ -> correct:true)
"""
import sys

EXPECTED = "academy{N6R4M_4N41Y515_15_73D10U5_FD56C357}"
# cipher->plain for a-z (digits/braces/underscore pass through)
C2P = dict(zip("abcdefghijklmnopqrstuvwxyz", "nyhqcjixfmwelvdoqargsubtpk"))


def decode(text: str) -> str:
    return "".join(C2P.get(ch, ch) if "a" <= ch <= "z" else ch
                   for ch in text.lower())


def solve(path: str = "message.txt") -> str:
    ct = open(path).read().strip()
    plain = decode(ct)
    assert plain.startswith("thereexistseveralother"), plain[:30]
    assert "theflagis" in plain
    tail = plain[plain.index("theflagis") + len("theflagis"):]
    flag = "academy" + tail[7:tail.index("}") + 1]
    assert flag == EXPECTED.lower(), flag
    print(plain[:120])
    print("...", plain[-80:])
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "message.txt"))
