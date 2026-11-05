#!/usr/bin/env python3
"""
Solver for Challenge 65: vault-door-7 (Reverse Engineering)
Decodes packed 32-bit big-endian integers into the vault password string.
"""

def solve() -> str:
    # 8 32-bit integers from VaultDoor7.checkPassword()
    ints = [
        1096770097,
        1952395366,
        1600270708,
        1601398833,
        1716808014,
        1734292791,
        895890230,
        808608100
    ]
    password_bytes = bytearray()
    for val in ints:
        password_bytes.extend(val.to_bytes(4, byteorder="big"))
    
    flag_inner = password_bytes.decode("ascii")
    return f"academy{{{flag_inner}}}"

if __name__ == "__main__":
    flag = solve()
    print("Flag:", flag)
