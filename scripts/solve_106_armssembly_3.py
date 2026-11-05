#!/usr/bin/env python3
"""
Solver for Challenge 106: ARMssembly 3 (Reverse Engineering)
Simulates ARMv8-A (AArch64) Hamming weight / popcount extraction loop in chall_3.S.
Platform: CyLab Security Academy / picoCTF 2021
"""

def func2(val: int) -> int:
    """
    Simulation of func2:
      func2:
        sub sp, sp, #16
        str w0, [sp, 12]
        ldr w0, [sp, 12]
        add w0, w0, 3
        add sp, sp, 16
        ret
    """
    return (val + 3) & 0xffffffff

def func1(arg: int) -> int:
    """
    Simulation of func1:
      1. Initializes accumulator to 0: [sp, 44] = 0
      2. Loops while arg != 0:
         - If (arg & 1) != 0, acc = func2(acc) -> acc += 3
         - arg >>= 1 (lsr w0, w0, 1)
      3. Returns acc.
      Effectively computes: popcount(arg) * 3
    """
    acc = 0
    w0 = arg & 0xffffffff
    while w0 != 0:
        if (w0 & 1) != 0:
            acc = func2(acc)
        w0 >>= 1
    return acc

def solve(arg: int = 605030239) -> str:
    result = func1(arg)
    hex_str = f"{result:08x}"
    return f"academy{{{hex_str}}}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
