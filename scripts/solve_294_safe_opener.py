#!/usr/bin/env python3
"""Solver for Challenge 294 Safe Opener (picoCTF 2022, Reverse Engineering).

Vuln: SafeOpener.java base64-encodes user input, then compares against
hard-coded "encodedkey" cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz — which is just
base64(password). Decode it -> password -> academy{...} wrapper.

Usage: solve_294_safe_opener.py
Verified: academy{pl3as3_l3t_m3_1nt0_th3_saf3} (POST /api/submissions/ -> correct:true)
"""
import base64

EXPECTED = "academy{pl3as3_l3t_m3_1nt0_th3_saf3}"
ENCODED = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz"


def solve() -> str:
    password = base64.b64decode(ENCODED).decode()
    flag = "academy{%s}" % password
    print(password, "->", flag)
    assert flag == EXPECTED
    return flag


if __name__ == "__main__":
    print(solve())
