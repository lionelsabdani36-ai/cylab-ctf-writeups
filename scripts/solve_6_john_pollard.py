#!/usr/bin/env python3
"""
Solver for Challenge 6: john_pollard (Cryptography)
Factors 53-bit RSA modulus from certificate and outputs flag.
"""
import math

def solve(n: int = 4966306421059967) -> str:
    for i in range(2, int(math.isqrt(n)) + 1):
        if n % i == 0:
            p = i
            q = n // i
            # In CyLab: academy{q,p} or academy{p,q}
            return f"academy{{{max(p, q)},{min(p, q)}}}"
    return "Failed to factor"

if __name__ == "__main__":
    print("Flag:", solve())
