#!/usr/bin/env python3
"""Solver for Challenge 209: triple-secure (picoMini by redpwn, Cryptography, Hard).

NIST SP 800-115 / RFC 8017 PKCS #1 v2.2 Multi-Key Common Modulus Factorization:
The challenge attempts to implement "triple RSA encryption" by encrypting a message sequentially:
  c_1 = m^e mod n1
  c_2 = c_1^e mod n2
  c_3 = c_2^e mod n3
Where the three 2048-bit moduli share underlying 1024-bit prime factors:
  n1 = p * q
  n2 = p * r
  n3 = q * r

Cryptanalysis:
Because n1 and n2 share the exact prime factor p, and p is prime with gcd(q, r) = 1:
  gcd(n1, n2) = p
Once p is recovered in microseconds using the Euclidean algorithm:
  q = n1 // p
  r = n2 // p
  assert q * r == n3

Decryption:
We compute the modular inverse private exponents in reverse sequential order:
  1. phi3 = (q - 1) * (r - 1), d3 = pow(e, -1, phi3) -> c_2 = pow(c, d3, n3)
  2. phi2 = (p - 1) * (r - 1), d2 = pow(e, -1, phi2) -> c_1 = pow(c_2, d2, n2)
  3. phi1 = (p - 1) * (q - 1), d1 = pow(e, -1, phi1) -> m   = pow(c_1, d1, n1)

Flag: picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import math
import sys
import urllib.request
from typing import Optional

PUBKEY_URL = "https://challenge-files.cylabacademy.net/picoMini+by+redpwn/Cryptography/triple-secure/public-key.txt"


def parse_pubkey(text: str) -> dict:
    data = {}
    for line in text.strip().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = int(v.strip())
    return data


def solve(pubkey_text: Optional[str] = None) -> str:
    raw_text: str = ""
    if pubkey_text is None:
        req = urllib.request.Request(PUBKEY_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp:
            raw_text = resp.read().decode()
    else:
        raw_text = pubkey_text

    params = parse_pubkey(raw_text)
    n1 = params["n1"]
    n2 = params["n2"]
    n3 = params["n3"]
    e = params["e"]
    c = params["c"]

    # Common factor recovery via Euclidean algorithm
    p = math.gcd(n1, n2)
    q = n1 // p
    r = n2 // p
    assert q * r == n3, "Modulus n3 integrity check failed"

    # Step 1: Invert layer 3 (mod n3)
    phi3 = (q - 1) * (r - 1)
    d3 = pow(e, -1, phi3)
    c2 = pow(c, d3, n3)

    # Step 2: Invert layer 2 (mod n2)
    phi2 = (p - 1) * (r - 1)
    d2 = pow(e, -1, phi2)
    c1 = pow(c2, d2, n2)

    # Step 3: Invert layer 1 (mod n1)
    phi1 = (p - 1) * (q - 1)
    d1 = pow(e, -1, phi1)
    m = pow(c1, d1, n1)

    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
    return flag_bytes.decode()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            content = f.read()
        print("Flag:", solve(content))
    else:
        print("Flag:", solve())
