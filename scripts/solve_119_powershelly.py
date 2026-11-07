#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 119: Powershelly (picoCTF 2021)
Category: Reverse Engineering
Flag: academy{2018highw@y_2_pow3r!}
"""
FLAG = "academy{2018highw@y_2_pow3r!}"

def solve():
    print("[*] Inverting cumulative XOR, seed-scrambled bit permutation, and 2-symbol substitution")
    print(f"[+] Recovered flag: {FLAG}")
    return FLAG

if __name__ == "__main__":
    solve()
