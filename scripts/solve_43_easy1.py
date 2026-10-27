#!/usr/bin/env python3
"""
Solver for Challenge 43: Easy1 (Cryptography)
Deciphers Vigenere / One-Time Pad ciphertext using the provided key.
"""

def solve(ciphertext: str = "UFJKXQZQUNB", key: str = "SOLVECRYPTO") -> str:
    plaintext = []
    for c, k in zip(ciphertext, key):
        c_val = ord(c) - ord('A')
        k_val = ord(k) - ord('A')
        p_val = (c_val - k_val) % 26
        plaintext.append(chr(p_val + ord('A')))
    return f"academy{{{''.join(plaintext)}}}"

if __name__ == "__main__":
    print("Flag:", solve())
