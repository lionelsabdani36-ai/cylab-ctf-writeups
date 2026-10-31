#!/usr/bin/env python3
"""
Solver for Challenge 412: Custom encryption (picoCTF 2024 / CyLab Academy).

Algorithm Breakdown:
1. Diffie-Hellman Key Exchange over F_p (p=97, g=31):
   Given public parameters a=94, b=22, compute shared_key = pow(g, a * b, p).
2. Integer Multiplication Decryption:
   cipher[i] = ord(semi_cipher[i]) * shared_key * 311.
   Recover semi_cipher[i] = chr(cipher[i] // (shared_key * 311)).
3. Dynamic Reversed XOR Decryption:
   semi_cipher was produced by reversing plaintext and XORing with repeating key 'trudeau'.
   Invert XOR with 'trudeau', then reverse string back to recover original flag.
"""
import sys

CIPHER = [
    226719, 1687797, 1637415, 50382, 25191, 100764, 1763370, 1712988, 1612224, 1058022,
    0, 2090853, 529011, 125955, 1712988, 0, 554202, 2166426, 25191, 1561842,
    604584, 680157, 151146, 151146, 428247, 151146, 654966, 302292, 629775, 579393,
    428247, 125955, 151146, 0
]
P = 97
G = 31
A = 94
B = 22
TEXT_KEY = "trudeau"


def solve(cipher=None, p=P, g=G, a=A, b=B, text_key=TEXT_KEY) -> str:
    if cipher is None:
        cipher = CIPHER
    shared_key = pow(g, a * b, p)
    factor = shared_key * 311

    semi_cipher = "".join(chr(c // factor) for c in cipher)

    key_len = len(text_key)
    reversed_plain = []
    for i, c in enumerate(semi_cipher):
        k_char = text_key[i % key_len]
        reversed_plain.append(chr(ord(c) ^ ord(k_char)))

    plaintext = "".join(reversed_plain)[::-1]
    return plaintext


if __name__ == "__main__":
    flag = solve()
    print(flag)
