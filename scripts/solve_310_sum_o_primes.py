#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 310: Sum-O-Primes
Category: Cryptography
Platform: picoCTF 2022
Points: 400

Vulnerability Analysis:
- Architecture: Standard RSA Cryptosystem with 1024-bit primes p and q.
- Cryptographic Flaw: The generator provides both the modulus n = p * q AND the sum of primes x = p + q.
- Mathematical Basis:
  The two primes are roots of the quadratic polynomial:
    (t - p)(t - q) = t^2 - (p + q)t + pq = t^2 - x*t + n = 0
  The discriminant Delta = (p + q)^2 - 4*p*q = x^2 - 4*n = (p - q)^2.
  Since Delta is a perfect square:
    sqrt(Delta) = |p - q|
    p = (x + isqrt(Delta)) // 2
    q = (x - isqrt(Delta)) // 2
  Once p and q are factored, compute Euler's totient phi = (p - 1) * (q - 1).
  The private key d = pow(e, -1, phi), and cleartext flag m = pow(c, d, n).

Flag: academy{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_b18bb8b6}
Verified: POST /api/submissions/ -> correct: true, HTTP 201 Created
"""

import math
import sys
import urllib.request

OUTPUT_URL = "https://challenge-files.cylabacademy.net/library/1b111803b415eef187e1c4caad0c8959648aef54325b05ab4fe629c7be228445/output.txt"

def solve_from_data(data: str) -> str:
    lines = [line.strip() for line in data.splitlines() if line.strip()]
    vals = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = int(v.strip(), 16)

    x = vals["x"]
    n = vals["n"]
    c = vals["c"]
    e = 65537

    # Quadratic discriminant: Delta = x^2 - 4*n
    delta = x * x - 4 * n
    sqrt_delta = math.isqrt(delta)
    if sqrt_delta * sqrt_delta != delta:
        raise ValueError("Discriminant is not a perfect square!")

    p = (x + sqrt_delta) // 2
    q = (x - sqrt_delta) // 2
    assert p * q == n, "Factored primes do not multiply to n!"

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
    flag = flag_bytes.decode("utf-8", "replace")
    return flag

def solve() -> str:
    print(f"[*] Fetching challenge output from {OUTPUT_URL}...")
    req = urllib.request.Request(OUTPUT_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        data = resp.read().decode("utf-8")

    flag = solve_from_data(data)
    print(f"[+] Decrypted Flag: {flag}")
    return flag

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            print(solve_from_data(f.read()))
    else:
        solve()
