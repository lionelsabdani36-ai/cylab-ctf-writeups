#!/usr/bin/env python3
"""
Solver for Challenge 16: asm2 (Reverse Engineering)
Simulates x86 disassembly loop execution for asm2(0xb, 0x1a).
"""

def asm2(arg1: int, arg2: int) -> int:
    """
    asm2 assembly translation:
      <+0>:  push ebp
      <+1>:  mov ebp, esp
      <+3>:  sub esp, 0x10
      <+6>:  mov eax, DWORD PTR [ebp+0xc]   ; arg2
      <+9>:  mov DWORD PTR [ebp-0x4], eax   ; local1 = arg2
      <+12>: mov eax, DWORD PTR [ebp+0x8]   ; arg1
      <+15>: mov DWORD PTR [ebp-0x8], eax   ; local2 = arg1
      <+18>: jmp <asm2+31>
      <+20>: add DWORD PTR [ebp-0x4], 0x1   ; local1 += 1
      <+24>: add DWORD PTR [ebp-0x8], 0xe7  ; local2 += 0xe7
      <+31>: cmp DWORD PTR [ebp-0x8], 0x5ed6
      <+38>: jle <asm2+20>
      <+40>: mov eax, DWORD PTR [ebp-0x4]
      <+43>: leave
      <+44>: ret
    """
    local1 = arg2
    local2 = arg1
    while local2 <= 0x5ed6:
        local1 = (local1 + 1) & 0xffffffff
        local2 = (local2 + 0xe7) & 0xffffffff
    return local1

def solve() -> str:
    result = asm2(0xb, 0x1a)
    return f"0x{result:x}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
