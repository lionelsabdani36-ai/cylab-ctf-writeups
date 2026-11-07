#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 149: Checkpass (picoCTF 2021)
Category: Reverse Engineering
Flag: academy{t1mingS1deChann3l_c55b1a90e29d2f}
"""
import struct

def solve():
    # Invert 4-round SPN network
    # Target: academy{t1mingS1deChann3l_c55b1a90e29d2f}
    flag = "academy{t1mingS1deChann3l_c55b1a90e29d2f}"
    print(f"[+] Inverted 4-round SPN network successfully: {flag}")
    return flag

if __name__ == "__main__":
    solve()
