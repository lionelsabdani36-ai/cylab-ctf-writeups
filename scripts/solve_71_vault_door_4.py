#!/usr/bin/env python3
"""
Solver for Challenge 71: vault-door-4 (Reverse Engineering)
Decodes decimal, hex, octal, and char array bytes into password string.
"""

def solve() -> str:
    row1 = [106 , 85  , 53  , 116 , 95  , 52  , 95  , 98]
    row2 = [0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f]
    row3 = [0o142, 0o131, 0o164, 0o63 , 0o163, 0o137, 0o70 , 0o70]
    row4 = [ord('a') , ord('3') , ord('1') , ord('d') , ord('a') , ord('d') , ord('6') , ord('c')]
    all_bytes = row1 + row2 + row3 + row4
    return f"academy{{{bytes(all_bytes).decode()}}}"

if __name__ == "__main__":
    print("Flag:", solve())
