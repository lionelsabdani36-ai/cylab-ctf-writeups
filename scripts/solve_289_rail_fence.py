#!/usr/bin/env python3
"""Solver for Challenge 289 rail-fence (picoCTF, Cryptography).

Challenge: rail-fence cipher with 4 rails. Decrypt message.txt, the decoded
message names the phrase -> academy{phrase}.

Usage: solve_289_rail_fence.py [message.txt path or URL] [rails=4]
"""
import sys
import urllib.request

URL = ("https://challenge-files.cylabacademy.net/library/"
       "e3a0d625f6dd6554233d2675553060046f8bf5b21af03458091011ad1fccc3d7/message.txt")


def decrypt(ct: str, rails: int = 4) -> str:
    n = len(ct)
    pat, r, d = [], 0, 1
    for _ in range(n):
        pat.append(r)
        r += d
        if r == rails - 1 or r == 0:
            d = -d
    rows, idx = [], 0
    for k in range(rails):
        L = pat.count(k)
        rows.append(ct[idx:idx + L])
        idx += L
    pos = [0] * rails
    out = []
    for k in pat:
        out.append(rows[k][pos[k]])
        pos[k] += 1
    return "".join(out)


def main(src=None, rails: int = 4) -> str:
    if src is None or (isinstance(src, str) and src.startswith("http")):
        with urllib.request.urlopen(src or URL, timeout=30) as r:
            ct = r.read().decode().strip()
    else:
        with open(src) as f:
            ct = f.read().strip()
    pt = decrypt(ct, rails)
    if pt.lower().startswith("the flag is:"):
        return "academy{" + pt.split(":", 1)[1].strip() + "}"
    return pt


if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else None
    r = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    print(main(a, r))
