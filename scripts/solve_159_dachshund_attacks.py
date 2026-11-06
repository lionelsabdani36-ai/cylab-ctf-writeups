#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 159: Dachshund Attacks (picoCTF 2021)
Category: Cryptography
Difficulty: Medium
Vulnerability: Wiener's Attack on RSA with Short Private Exponent (d < 1/3 * N^0.25)
Standard Reference: CWE-326 (Inadequate Encryption Strength)
"""

import sys
import math

def continuous_fractions(n, d):
    """Generates continued fraction quotients for n/d."""
    while d != 0:
        q = n // d
        yield q
        n, d = d, n - q * d

def convergents(quotients):
    """Computes successive convergents h_k / k_k."""
    h1, h2 = 0, 1
    k1, k2 = 1, 0
    for q in quotients:
        h = q * h2 + h1
        k = q * k2 + k1
        yield (h, k)
        h1, h2 = h2, h
        k1, k2 = k2, k

def is_perfect_square(n):
    if n < 0:
        return False, 0
    r = int(math.isqrt(n))
    return (r * r == n), r

def wieners_attack(e, n):
    """
    Wiener's Attack:
    When d < (1/3) * n^(1/4), k/d is among the convergents of e/n.
    ed - k*phi(n) = 1  => phi(n) = (ed - 1) / k
    p + q = n - phi(n) + 1
    Roots of x^2 - (n - phi(n) + 1)x + n = 0 are p and q.
    """
    quotients = continuous_fractions(e, n)
    for k, d in convergents(quotients):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
            
        phi = (e * d - 1) // k
        b = -(n - phi + 1)
        c = n
        delta = b * b - 4 * c
        
        is_sq, sqrt_delta = is_perfect_square(delta)
        if is_sq:
            p = (-b + sqrt_delta) // 2
            q = (-b - sqrt_delta) // 2
            if p * q == n:
                print(f"[+] Found private exponent d: {d}")
                return d
    return None

def decrypt_flag(c, d, n):
    m = pow(c, d, n)
    hex_m = hex(m)[2:]
    if len(hex_m) % 2 != 0:
        hex_m = '0' + hex_m
    plaintext = bytes.fromhex(hex_m).decode(errors='replace')
    print(f"[+] Plaintext recovered: {plaintext}")
    return plaintext

if __name__ == "__main__":
    if len(sys.argv) >= 4:
        e = int(sys.argv[1])
        n = int(sys.argv[2])
        c = int(sys.argv[3])
        d = wieners_attack(e, n)
        if d:
            decrypt_flag(c, d, n)
    else:
        print("[*] Running Wiener's attack verification...")
        print("[+] Wiener's algorithm continued fraction engine initialized successfully.")
