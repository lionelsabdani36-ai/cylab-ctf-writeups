#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 315: Very Smooth
Category: Cryptography
Platform: picoCTF 2022
Points: 300

Vulnerability Analysis:
- Architecture: 2048-bit RSA modulus n = p * q with e = 65537.
- Cryptographic Flaw: Unsafe Prime Generation with B-smooth (p - 1).
  The primes p and q are generated such that all prime factors of (p - 1) and (q - 1)
  are small (smoothness <= 17 bits, with remaining bitcnt <= 24 bits).
- Mathematical Basis (Pollard's p-1 Algorithm):
  If all prime factors of (p - 1) are <= B (B-smooth), then (p - 1) divides:
    M = prod_{r <= B} r^{floor(log_r(B))}
  By Fermat's Little Theorem:
    a^(p - 1) = 1 (mod p)  ==>  a^M = 1 (mod p)
    ==> p divides (a^M - 1)
  Therefore, gcd(a^M - 1, n) will reveal p (as long as a^M != 1 mod q).
  Once p is found, q = n // p, phi = lcm(p - 1, q - 1), d = pow(e, -1, phi),
  and cleartext flag m = pow(c, d, n).

Flag: academy{p0ll4rd_f4ct0r1z4at10n_FTW_48d4cbdf}
Verified: POST /api/submissions/ -> correct: true, HTTP 201 Created
"""

import math
import sys
import urllib.request

OUTPUT_URL = "https://challenge-files.cylabacademy.net/library/3ebff3b5e7ef7f10a227bd1c96e451f81d1849f8b7c29b1d27e76e8529d83a66/output.txt"

def solve_from_data(data: str) -> str:
    lines = [line.strip() for line in data.splitlines() if line.strip()]
    vals = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = int(v.strip(), 16)

    n = vals["n"]
    c = vals["c"]
    e = 65537

    # Sieve primes up to B = 2^17
    B = 2**17  # 131072
    print(f"[*] Sieve primes up to smoothness bound B = {B}...")
    sieve = [True] * (B + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(B**0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = [False] * len(sieve[i*i::i])

    primes = [p for p in range(2, B + 1) if sieve[p]]
    print(f"[*] Executing Pollard's p - 1 factoring over {len(primes)} primes...")

    a = 2
    p = None
    for idx, prime in enumerate(primes):
        k = 1
        while k * prime <= B:
            k *= prime
        a = pow(a, k, n)
        if idx % 1000 == 0:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                p = g
                break

    if p is None:
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            p = g
        else:
            raise RuntimeError("Pollard's p - 1 failed to factor n within bound!")

    q = n // p
    assert p * q == n, "Factored primes do not multiply to n!"
    print(f"[+] Successfully factored modulus n into p and q!")

    phi = math.lcm(p - 1, q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
    flag = flag_bytes.decode("utf-8", "replace")
    print(f"[+] Decrypted Flag: {flag}")
    return flag

def solve() -> str:
    print(f"[*] Fetching challenge output from {OUTPUT_URL}...")
    req = urllib.request.Request(OUTPUT_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        data = resp.read().decode("utf-8")

    return solve_from_data(data)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            print(solve_from_data(f.read()))
    else:
        solve()
