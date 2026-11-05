#!/usr/bin/env python3
"""
Solver for Challenge 72: asm3 (Reverse Engineering)
Simulates x86 disassembly register operations for asm3(0xcc000a09, 0xcdb0b591, 0xc1116756).
"""

def asm3(arg1: int, arg2: int, arg3: int) -> int:
    """
    asm3 assembly translation:
      <+0>:  push   ebp
      <+1>:  mov    ebp,esp
      <+3>:  xor    eax,eax
      <+5>:  mov    ah,BYTE PTR [ebp+0xb]
      <+8>:  shl    ax,0x10
      <+12>: sub    al,BYTE PTR [ebp+0xe]
      <+15>: add    ah,BYTE PTR [ebp+0xf]
      <+18>: xor    ax,WORD PTR [ebp+0x12]
      <+22>: nop
      <+23>: pop    ebp
      <+24>: ret
    """
    # Memory layout relative to EBP:
    # [ebp+0x8..0xb]  = arg1 bytes (little-endian)
    # [ebp+0xc..0xf]  = arg2 bytes
    # [ebp+0x10..0x13] = arg3 bytes
    arg1_bytes = arg1.to_bytes(4, byteorder="little")
    arg2_bytes = arg2.to_bytes(4, byteorder="little")
    arg3_bytes = arg3.to_bytes(4, byteorder="little")
    
    # Combined stack frame bytes starting at ebp+0x8:
    stack = arg1_bytes + arg2_bytes + arg3_bytes
    
    # Helper to read byte at ebp + offset:
    def get_byte(offset: int) -> int:
        return stack[offset - 8]
    
    # Helper to read 16-bit word at ebp + offset:
    def get_word(offset: int) -> int:
        idx = offset - 8
        return stack[idx] | (stack[idx + 1] << 8)
    
    # <+3>: xor eax, eax
    eax = 0
    al = 0
    ah = 0
    
    # <+5>: mov ah, BYTE PTR [ebp+0xb]
    ah = get_byte(0xb)
    ax = (ah << 8) | al
    
    # <+8>: shl ax, 0x10
    # In x86 16-bit registers, shifting ax left by 16 clears all 16 bits
    ax = (ax << 16) & 0xffff
    al = ax & 0xff
    ah = (ax >> 8) & 0xff
    
    # <+12>: sub al, BYTE PTR [ebp+0xe]
    al = (al - get_byte(0xe)) & 0xff
    ax = (ah << 8) | al
    
    # <+15>: add ah, BYTE PTR [ebp+0xf]
    ah = (ah + get_byte(0xf)) & 0xff
    ax = (ah << 8) | al
    
    # <+18>: xor ax, WORD PTR [ebp+0x12]
    ax = (ax ^ get_word(0x12)) & 0xffff
    
    return ax

def solve() -> str:
    result = asm3(0xcc000a09, 0xcdb0b591, 0xc1116756)
    return f"0x{result:x}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
