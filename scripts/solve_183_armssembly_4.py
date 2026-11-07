#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 183: ARMssembly 4 (picoCTF 2021)
Category: Reverse Engineering
Flag: academy{3988daab}
"""
def solve(arg_a=965270072):
    w0 = arg_a
    if w0 > 100:
        w0 += 100
        if w0 > 499:
            w0 += 13
            w0 += 2
    flag = f"academy{{{w0:08x}}}"
    print(f"[+] Recovered flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
