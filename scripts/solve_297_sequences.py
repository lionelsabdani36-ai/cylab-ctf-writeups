#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 297: Sequences
Category: Cryptography
Platform: picoCTF 2022
Points: 400

Vulnerability Analysis:
- Algorithm Problem: Computing m_func(2e7) for a 4th-order linear recurrence relation:
    m(i) = 21*m(i-1) + 301*m(i-2) - 9549*m(i-3) + 55692*m(i-4)
    with base cases: m(0) = 1, m(1) = 2, m(2) = 3, m(3) = 4.
- Recurrence Analysis & Matrix Diagonalization / Characteristic Roots:
  Characteristic equation:
    lambda^4 - 21*lambda^3 - 301*lambda^2 + 9549*lambda - 55692 = 0
  Factoring yields integer roots:
    (lambda - 17)(lambda - 13)(lambda - 12)(lambda + 21) = 0
    Roots: lambda_1 = -21, lambda_2 = 12, lambda_3 = 13, lambda_4 = 17.
- Closed-Form Derivation:
  m(i) = c_1 * (-21)^i + c_2 * 12^i + c_3 * 13^i + c_4 * 17^i
  Solving initial conditions:
    c_1 = 403 / 10659 = 1612 / 42636
    c_2 = 760 / 33    = 981920 / 42636
    c_3 = -1727 / 68  = -1082829 / 42636
    c_4 = 253 / 76    = 141933 / 42636
  Common denominator D = 42636.
  We compute S = 42636 * m(ITERS) mod (10^10000 * 42636) in O(log(ITERS)) time via pow(base, ITERS, M).
  Then sol = (S // 42636) mod 10^10000.
  Verify MD5(sol) and XOR decrypt encrypted flag with SHA256(sol).

Flag: academy{b1g_numb3rs_56b2970a}
Verified: POST /api/submissions/ -> correct: true, HTTP 201 Created
"""

import hashlib
import sys

sys.set_int_max_str_digits(25000)

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("53c1beea6e427b3de1acf4834baed794f4bbd0dfe1d85f6a248ba4c12b")

def solve() -> str:
    print(f"[*] Solving 4th order linear recurrence for i = {ITERS}...")
    MOD = 10**10000
    D = 42636
    M = MOD * D

    # Numerators matching characteristic roots [-21, 12, 13, 17]
    n1 = 1612
    n2 = 981920
    n3 = -1082829
    n4 = 141933

    t1 = (n1 * pow(-21, ITERS, M)) % M
    t2 = (n2 * pow(12, ITERS, M)) % M
    t3 = (n3 * pow(13, ITERS, M)) % M
    t4 = (n4 * pow(17, ITERS, M)) % M

    S = (t1 + t2 + t3 + t4) % M
    if S % D != 0:
        raise ValueError("Composite sum is not divisible by common denominator!")

    sol = (S // D) % MOD
    sol_str = str(sol)

    sol_md5 = hashlib.md5(sol_str.encode()).hexdigest()
    if sol_md5 != VERIF_KEY:
        raise ValueError(f"MD5 mismatch! Expected {VERIF_KEY}, got {sol_md5}")

    key = hashlib.sha256(sol_str.encode()).digest()
    flag = bytearray([b ^ key[i] for i, b in enumerate(ENCRYPTED_FLAG)]).decode("utf-8")
    print(f"[+] Decrypted Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
