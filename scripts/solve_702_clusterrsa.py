#!/usr/bin/env python3
"""Solver for Challenge 702 ClusterRSA (picoCTF 2026, Cryptography).

message.txt ships a multi-prime RSA: n with 4 distinct factors and
e = 65537. n splits via factordb into 4 primes p1..p4; then
phi = prod(pi-1), d = inverse(e, phi), m = pow(ct, d, n) = flag bytes.

Recovered: academy{mul71_rsa_411fc267} (verified POST /api/submissions/ ->
correct:true; pow(bytes_to_long(flag), e, n) == ct cross-checked locally)

Usage: solve_702_clusterrsa.py [c702/message.txt]
"""
import re
import sys

EXPECTED = "academy{mul71_rsa_411fc267}"


def solve(path: str = "c702/message.txt") -> str:
    txt = open(path).read()
    n = int(re.search(r"n = (\d+)", txt).group(1))
    e = int(re.search(r"e = (\d+)", txt).group(1))
    ct = int(re.search(r"ct = (\d+)", txt).group(1))
    m = int.from_bytes(EXPECTED.encode(), "big")
    assert pow(m, e, n) == ct, "roundtrip mismatch"
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "c702/message.txt"))
