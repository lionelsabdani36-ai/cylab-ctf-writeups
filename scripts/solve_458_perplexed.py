#!/usr/bin/env python3
"""Solver for Challenge 458 - perplexed (picoCTF 2025, Reverse Engineering).

The challenge binary 'perplexed' is an unstripped 64-bit ELF executable.
Disassembly analysis of the 'check' function:
1. Validates input length: strlen(input) == 0x1b (27 characters including newline from fgets).
2. Contains an overlapping 23-byte reference buffer initialized on the stack:
   [rbp-0x50]: 0x61fb7cbb4c0e8fc3
   [rbp-0x48]: 0xd269df5b5afc9db9
   [rbp-0x41]: 0xf467edf4ed1bfed2 (offset 15 from -0x50)
3. Traverses the reference buffer bit-by-bit (MSB to LSB across 23 bytes = 184 bits).
4. For each input character, it tests 7 bits (bits 1 to 7, skipping bit 0 / MSB).
5. Comparing bit-by-bit against the reference bitstream reconstructs:
   academy{0n3_bi7_4t_a_7im3}

Verified: academy{0n3_bi7_4t_a_7im3} (POST /api/submissions/ -> correct:true)
"""
import struct
import sys

EXPECTED_FLAG = "academy{0n3_bi7_4t_a_7im3}"


def solve() -> str:
    # Reconstruct stack buffer at [rbp-0x50]
    b1 = struct.pack("<Q", 0x61FB7CBB4C0E8FC3)
    b2 = struct.pack("<Q", 0xD269DF5B5AFC9DB9)
    b3 = struct.pack("<Q", 0xF467EDF4ED1BFED2)

    ref = bytearray(23)
    ref[0:8] = b1
    ref[8:16] = b2
    ref[15:23] = b3  # overlaps by 1 byte at index 15

    # Extract 184 bits (MSB first)
    bits = []
    for b in ref:
        for bit_idx in range(8):
            mask = 1 << (7 - bit_idx)
            bits.append(1 if (b & mask) > 0 else 0)

    # Reconstruct 7-bit ASCII characters (skipping MSB bit 0)
    recovered_chars = []
    curr_char = 0
    input_bit = 0
    bit_pos = 0

    while bit_pos < len(bits):
        if input_bit == 0:
            input_bit += 1  # skip MSB (bit 0)

        if bits[bit_pos]:
            curr_char |= 1 << (7 - input_bit)

        bit_pos += 1
        input_bit += 1
        if input_bit == 8:
            recovered_chars.append(curr_char)
            curr_char = 0
            input_bit = 0
            if len(recovered_chars) == 26:
                break

    flag = bytes(recovered_chars).decode("ascii")
    print(f"[+] Recovered flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    solve()
