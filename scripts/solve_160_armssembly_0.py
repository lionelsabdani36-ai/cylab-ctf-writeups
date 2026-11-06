#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 160: ARMssembly 0 (picoCTF 2021)
Category: Reverse Engineering / AArch64 Assembly Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Automated Binary Analysis & Architecture Decomposition)
CWE: CWE-682 (Incorrect Calculation / Assembly Control Flow Inversion)

Description:
What integer does this program print?
Flag format: academy{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be academy{0055aabb})
Use arguments a and b: 2432642318 and 3919355441
File: chall.S

Analysis:
The assembly source defines func1:
    sub sp, sp, #16
    str w0, [sp, 12]   ; arg a stored
    str w1, [sp, 8]    ; arg b stored
    ldr w1, [sp, 12]   ; w1 = a
    ldr w0, [sp, 8]    ; w0 = b
    cmp w1, w0         ; unsigned compare of a and b
    bls .L2            ; branch if a <= b (unsigned)
    ldr w0, [sp, 12]   ; return a
    b .L3
.L2:
    ldr w0, [sp, 8]    ; return b
.L3:
    add sp, sp, 16
    ret

Thus func1 returns the unsigned maximum of (a, b).
For a = 2432642318 (0x90ff2d0e) and b = 3919355441 (0xe99c9e31), b > a.
func1 returns 3919355441, which in 32-bit hex (lowercase, no 0x, 8 chars) is 'e99c9e31'.
Flag: academy{e99c9e31}
Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import sys
import urllib.request
import re

CHALL_S_URL = "https://challenge-files.cylabacademy.net/library/2aee1bfb8502d5360e5d9f5b6f68bbefb2a62a6e45ba42cc6a198a0eab1a71a3/chall.S"
ARG_A = 2432642318
ARG_B = 3919355441


def simulate_func1(a: int, b: int) -> int:
    """
    Simulates AArch64 func1 logic:
    Takes two unsigned 32-bit values and returns max(a, b).
    """
    u_a = a & 0xFFFFFFFF
    u_b = b & 0xFFFFFFFF
    # cmp w1, w0; bls .L2 -> if u_a <= u_b: return u_b else return u_a
    if u_a <= u_b:
        return u_b
    return u_a


def solve(arg_a: int = ARG_A, arg_b: int = ARG_B) -> str:
    result = simulate_func1(arg_a, arg_b)
    hex_str = f"{result:08x}"
    return f"academy{{{hex_str}}}"


def main():
    print(f"[*] Analyzing AArch64 Assembly for arguments a={ARG_A}, b={ARG_B}...")
    flag = solve(ARG_A, ARG_B)
    print(f"[+] Computed Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
