#!/usr/bin/env python3
"""Solver for Challenge 713 Related Messages (picoCTF 2026, Cryptography).

chall.py: e=0x11 RSA, m2 = m1 + 3 (output shows Message - Message_fixed =
-3), c1 = m1^e mod N, c2 = m2^e mod N. Classic Franklin-Reiter related-message
attack: g1(x) = x^e - c1, g2(x) = (x+3)^e - c2 share root m1 over Z_N.
gcd(g1, g2) mod N is linear (x - m1) since e=17 is tiny; polynomial GCD with
coefficients mod N recovers m1 directly, no factoring needed.

Recovered: academy{m3ssage_w1th_typ0} (verified POST /api/submissions/ ->
correct:true)

Usage: solve_713_related_messages.py [c713/output.txt]
"""
import re
import sys

try:
    from Crypto.Util.number import long_to_bytes
except ImportError:
    sys.exit("needs pycryptodome: pip install pycryptodome")

EXPECTED = "academy{m3ssage_w1th_typ0}"
E = 0x11
DELTA = 3


def pmul(a, b, N):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            r[i + j] = (r[i + j] + x * y) % N
    return r


def psub(a, b, N):
    n = max(len(a), len(b))
    a = [0] * (n - len(a)) + a
    b = [0] * (n - len(b)) + b
    return [(x - y) % N for x, y in zip(a, b)]


def pmod(a, b, N):
    a = list(a)
    while len(a) >= len(b) and any(a):
        c = a[0] * pow(b[0], -1, N) % N
        k = len(a) - len(b)
        sub = [(c * x) % N for x in b] + [0] * k
        a = [(x - y) % N for x, y in zip(a, sub)]
        while a and a[0] == 0:
            a.pop(0)
    return a or [0]


def solve(path: str = "c713/output.txt") -> str:
    nums = [int(x) for x in re.findall(r"\d+", open(path).read())]
    c1, c2 = nums[0], nums[1]
    N = nums[-1]  # lines: c1, c2, (Message-Message_fixed), N
    g1 = [1] + [0] * (E - 1) + [(-c1) % N]
    p = [1]
    for _ in range(E):
        p = pmul(p, [1, DELTA], N)
    g2 = psub(p, [c2 % N], N)
    a, b = g1, g2
    while any(b):
        a, b = b, pmod(a, b, N)
    m1 = (-a[1] * pow(a[0], -1, N)) % N
    # output stores Message - Message_fixed = -3, i.e. m1 = m_fixed - 3;
    # the printable flag is m1 + DELTA
    for cand in (m1 + DELTA, m1 - DELTA, m1):
        try:
            s = long_to_bytes(cand).decode()
        except Exception:
            continue
        if s.startswith("academy{") and s.endswith("}"):
            return s
    return long_to_bytes(m1 + DELTA).decode()


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "c713/output.txt"))
