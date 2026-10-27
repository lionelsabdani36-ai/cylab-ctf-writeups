#!/usr/bin/env python3
"""
Solver for Challenge 162: Mind your Ps and Qs (Module 138, LP 17)
CyLab Security Academy / picoCTF 2021
Vulnerability: Weak RSA Modulus (Small N ~270 bits factorable via Pollard's Rho / FactorDB)
"""
import urllib.request
import json
import sys

def solve():
    c = 717608817902276639011922897702552744324264244069272484013719744328086856277690292
    n = 1368992139315019955067447961537607041364451719382349005056752379702694554965203011
    e = 65537

    # Factors from factorization of N (82 digits, 270 bits)
    p = 2074606527507983503944226222695401999839
    q = 659880377875535146491994798968813949893149

    assert p * q == n, "Factorization check failed!"

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    flag = m.to_bytes((m.bit_length() + 7) // 8, 'little').decode('utf-8').strip()
    print("Flag:", flag)
    return flag

if __name__ == "__main__":
    solve()
