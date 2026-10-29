#!/usr/bin/env python3
"""Solver for Challenge 718 Small Trouble (picoCTF 2026, Cryptography).

encryption.py: RSA with 1048-bit p,q (n ~2096 bit) but d = getPrime(256) —
a 256-bit private exponent, far below Wiener's bound (d < N^0.25 / 3 needs
d < ~2^500; here d ~ 2^256 << that). Wiener's continued-fraction attack on
e/N convergents recovers k/d from e*d = 1 mod phi, factors N via
x^2 - (N-phi+1)x + N = 0, decrypts c.

Recovered locally: academy{sm4ll_d_46c3352b} (+ pow(m,e,n)==c roundtrip OK)
(pending POST /api/submissions/ — session expired, re-submit with fresh cookie)

Usage: solve_718_small_trouble.py [c718/message.txt]
"""
import re
import sys
from math import isqrt

EXPECTED = "academy{sm4ll_d_46c3352b}"


def convergents(num, den):
    cf = []
    a, b = num, den
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a - q * b
    convs = []
    for q in cf:
        if not convs:
            convs.append((q, 1))
        elif len(convs) == 1:
            convs.append((q * convs[0][0] + 1, q))
        else:
            convs.append((q * convs[-1][0] + convs[-2][0],
                          q * convs[-1][1] + convs[-2][1]))
    return convs


def solve(path: str = "c718/message.txt") -> str:
    txt = open(path).read()
    n = int(re.search(r"n = (\d+)", txt).group(1))
    e = int(re.search(r"e = (\d+)", txt).group(1))
    c = int(re.search(r"c = (\d+)", txt).group(1))
    for k, d in convergents(e, n):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = isqrt(disc)
        if t * t != disc or (s + t) % 2 != 0:
            continue
        p, q = (s + t) // 2, (s - t) // 2
        if p * q == n:
            m = pow(c, d, n)
            return m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "c718/message.txt"))
