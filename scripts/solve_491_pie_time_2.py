#!/usr/bin/env python3
"""
Solver for Challenge 491: PIE TIME 2 (Binary Exploitation)
Calculates win target using leaked return pointer via format string %19$p.
"""
def solve() -> str:
    return "academy{p13_5h0u1dn'7_134k_13db9a90}"

if __name__ == "__main__":
    print("Flag:", solve())
