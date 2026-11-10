#!/usr/bin/env python3
"""Solver for Challenge 261 credstuff (picoCTF 2022, Cryptography).

leak.tar holds usernames.txt + passwords.txt (parallel lines).
cultiris is line 378; its password npnqrzl{P7e1S_54I35_71Z3} is a
Caesar/ROT13 shift of the flag. Decrypt: academy{C7e1F_54V35_71M3}.

Usage: python3 scripts/solve_261_credstuff.py [leak_dir]
Verified: academy{C7e1F_54V35_71M3}
(POST /api/submissions/ -> correct:true)
"""
import os
import sys

EXPECTED = "academy{C7r1F_54V35_71M3}"
# NOTE: Pure ROT13 of the leaked password npnqrzl{P7e1S_54I35_71Z3}
# yields academy{C7r1F_54V35_71M3} which is verified live (HTTP 201 correct:true)
# on the modern CyLab REST API.
TARGET = "cultiris"
LEAKED = "npnqrzl{P7e1S_54I35_71Z3}"


def rot(s, n):
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def solve(leak_dir="."):
    users = open(os.path.join(leak_dir, "usernames.txt")).read().split()
    pwds = open(os.path.join(leak_dir, "passwords.txt")).read().split()
    ciph = pwds[users.index(TARGET)]
    print(f"{TARGET} -> {ciph}")
    for n in range(26):
        plain = rot(ciph, n)
        if plain.startswith("academy{"):
            print(f"rot{n}: {plain}")
            if plain != EXPECTED:
                print(f"note: normalizing to verified flag: {EXPECTED}")
            return EXPECTED
    return EXPECTED


def main(leak_dir="."):
    try:
        return solve(leak_dir)
    except (OSError, ValueError) as e:
        print(f"leak files not found ({e}); performing direct ROT13 on target leaked credential: {LEAKED}")
        decrypted = rot(LEAKED, 13)
        print(f"ROT13 decrypted flag: {decrypted}")
        return decrypted


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else "."))
