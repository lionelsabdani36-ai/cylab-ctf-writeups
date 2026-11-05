#!/usr/bin/env python3
"""
Solver for Challenge 150: ARMssembly 2 (Reverse Engineering)
Simulates ARMv8-A (AArch64) assembly loop execution and unsigned condition branching for chall_2.S.
Platform: CyLab Security Academy / picoCTF 2021
"""

def func1(arg: int) -> int:
    """
    Simulation of ARMv8 AArch64 func1 logic:
      func1:
        sub sp, sp, #32
        str w0, [sp, 12]   ; store input arg (32-bit)
        str wzr, [sp, 24]  ; acc = 0
        str wzr, [sp, 28]  ; i = 0
        b   .L2
      .L3:
        ldr w0, [sp, 24]   ; load acc
        add w0, w0, 3      ; acc += 3
        str w0, [sp, 24]
        ldr w0, [sp, 28]   ; load i
        add w0, w0, 1      ; i += 1
        str w0, [sp, 28]
      .L2:
        ldr w1, [sp, 28]   ; w1 = i
        ldr w0, [sp, 12]   ; w0 = arg
        cmp w1, w0         ; unsigned comparison via carry flag (bcc = branch if carry clear / unsigned lower)
        bcc .L3
        ldr w0, [sp, 24]   ; return acc
        add sp, sp, 32
        ret
    """
    # The loop increments acc by 3 exactly 'arg' times (unsigned 32-bit):
    # acc = (arg * 3) & 0xffffffff
    w0 = arg & 0xffffffff
    acc = (w0 * 3) & 0xffffffff
    return acc

def solve(arg: int = 2729572966) -> str:
    result = func1(arg)
    hex_str = f"{result:08x}"
    return f"academy{{{hex_str}}}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
