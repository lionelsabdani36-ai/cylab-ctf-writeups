#!/usr/bin/env python3
"""Solver for Challenge 312 transposition-trial (picoCTF 2022, Cryptography).

Every block of 3 chars got rotated: last char moved to front. So to recover,
rotate each block the other way. First block 'heT' -> 'The' confirms direction.

Usage: solve_312_transposition_trial.py [message.txt path]
Verified: academy{7R4N5P051N6_15_3XP3N51V3_5571D3F8} (POST /api/submissions/ -> correct:true)
"""
import sys

EXPECTED = "academy{7R4N5P051N6_15_3XP3N51V3_5571D3F8}"


def solve(path: str = "message.txt") -> str:
    raw = open(path).read().strip()
    assert len(raw) % 3 == 0, "length %d not multiple of 3" % len(raw)
    out = "".join(b[-1] + b[:2] for b in
                  (raw[i:i + 3] for i in range(0, len(raw), 3)))
    assert out.startswith("The flag is "), out[:20]
    import re
    m = re.search(r"academy\{[^}]*\}", out)
    assert m, "no flag found in decoded text"
    flag = m.group(0)
    print(out)
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "message.txt"))
