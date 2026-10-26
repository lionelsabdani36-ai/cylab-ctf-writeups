#!/usr/bin/env python3
"""
Solver for Challenge 64: caesar (Cryptography)
Playlist 17: Cryptography and Challenge Library Learning Intro (Module 133)
Ciphertext: academy{jyvzzpunaolybipjvubsxjvqwk}
Flag: academy{crossingtherubiconulqcojpd}
"""

def solve():
    enc = "jyvzzpunaolybipjvubsxjvqwk"
    # Brute-force all 25 shifts
    candidates = {}
    for shift in range(1, 26):
        decrypted = ""
        for c in enc:
            if 'a' <= c <= 'z':
                decrypted += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted += c
        candidates[shift] = decrypted
        if "crossingtherubicon" in decrypted:
            return f"academy{{{decrypted}}}"
    return candidates

if __name__ == "__main__":
    print("Flag:", solve())
