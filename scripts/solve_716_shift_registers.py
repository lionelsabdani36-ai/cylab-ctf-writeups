#!/usr/bin/env python3
"""
Solver for Challenge 716: shift registers (picoCTF 2026 / CyLab Academy).

Algorithm Breakdown:
1. The challenge uses an 8-bit Linear Feedback Shift Register (LFSR) seeded by
   key & 0xFF. Despite generating 126 random bytes for the key, only the least
   significant byte (key & 0xFF) is used as the initial LFSR state.
2. The LFSR state space is exactly 2^8 = 256 possible initial values.
3. For each candidate state in [0, 255], step the LFSR sequentially:
   feedback = ((state >> 7) & 1) ^ ((state >> 5) & 1) ^ ((state >> 4) & 1) ^ ((state >> 3) & 1)
   state = (feedback << 7) | (state >> 1)
   ks = state
   keystream byte XOR ciphertext byte recovers the candidate plaintext.
4. Filter candidates containing 'academy{' to uniquely isolate the flag.
"""
import sys

CIPHERTEXT_HEX = "30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9"


def steplfsr(lfsr: int) -> int:
    b7 = (lfsr >> 7) & 1
    b5 = (lfsr >> 5) & 1
    b4 = (lfsr >> 4) & 1
    b3 = (lfsr >> 3) & 1
    feedback = b7 ^ b5 ^ b4 ^ b3
    return (feedback << 7) | (lfsr >> 1)


def solve(ct_hex: str = CIPHERTEXT_HEX) -> str:
    ct = bytes.fromhex(ct_hex.strip())
    for init in range(256):
        lfsr = init
        pt = bytearray()
        for c in ct:
            lfsr = steplfsr(lfsr)
            pt.append(c ^ lfsr)
        if b"academy{" in pt:
            return pt.decode("latin1")
    raise ValueError("Flag not found in search space")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else CIPHERTEXT_HEX
    print(solve(target))
