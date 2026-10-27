#!/usr/bin/env python3
"""
Solver for Challenge 60: vault-door-3 (Reverse Engineering)
Inverts buffer permutation in VaultDoor3.java.
"""

def solve(target: str = "jU5t_a_sna_3lpm12ga4b_u_4_mfrc46") -> str:
    password = ['?'] * 32
    # 0..7
    for i in range(8):
        password[i] = target[i]
    # 8..15
    for i in range(8, 16):
        password[23 - i] = target[i]
    # 16..31 step 2
    for i in range(16, 32, 2):
        password[46 - i] = target[i]
    # 31 down to 17 step -2
    for i in range(31, 16, -2):
        password[i] = target[i]
    return f"academy{{{''.join(password)}}}"

if __name__ == "__main__":
    print("Flag:", solve())
