#!/usr/bin/env python3
"""
Solver for Challenge 20: asm1 (Reverse Engineering)
Simulates x86 conditional branch execution for asm1(0xb70).
"""

def asm1(arg: int) -> int:
    """
    asm1 assembly logic:
      <+0>:  push   ebp
      <+1>:  mov    ebp,esp
      <+3>:  cmp    DWORD PTR [ebp+0x8],0x6af
      <+10>: jg     <asm1+37>
      <+12>: cmp    DWORD PTR [ebp+0x8],0x465
      <+19>: jne    <asm1+29>
      <+21>: mov    eax,DWORD PTR [ebp+0x8]
      <+24>: add    eax,0x17
      <+27>: jmp    <asm1+60>
      <+29>: mov    eax,DWORD PTR [ebp+0x8]
      <+32>: sub    eax,0x17
      <+35>: jmp    <asm1+60>
      <+37>: cmp    DWORD PTR [ebp+0x8],0xb70
      <+44>: jne    <asm1+54>
      <+46>: mov    eax,DWORD PTR [ebp+0x8]
      <+49>: sub    eax,0x17
      <+52>: jmp    <asm1+60>
      <+54>: mov    eax,DWORD PTR [ebp+0x8]
      <+57>: add    eax,0x17
      <+60>: pop    ebp
      <+61>: ret
    """
    if arg > 0x6af:
        if arg != 0xb70:
            return (arg + 0x17) & 0xffffffff
        else:
            return (arg - 0x17) & 0xffffffff
    else:
        if arg != 0x465:
            return (arg - 0x17) & 0xffffffff
        else:
            return (arg + 0x17) & 0xffffffff

def solve(arg: int = 0xb70) -> str:
    res = asm1(arg)
    return f"0x{res:x}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
