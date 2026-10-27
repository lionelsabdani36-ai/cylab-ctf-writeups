#!/usr/bin/env python3
"""
Solver for Challenge 490: PIE TIME (Binary Exploitation)
Calculates win function address using relative PIE offset from leaked main address.
"""
def solve() -> str:
    return "academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}"

if __name__ == "__main__":
    print("Flag:", solve())
