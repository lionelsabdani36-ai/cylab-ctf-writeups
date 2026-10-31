#!/usr/bin/env python3
"""
Solver for Challenge 703: cryptomaze (picoCTF 2026 / CyLab Academy).

Algorithm Breakdown:
1. The challenge specifies an LFSR of length 64 initialized with a known state
   and taps at [63, 61, 60, 58].
2. For 128 clock cycles:
   - Compute feedback bit = state[63] ^ state[61] ^ state[60] ^ state[58].
   - Shift left: pop state[0], append feedback bit to state.
   - Output bit is the popped state[0].
3. Pack the 128 output bits into 16 bytes (8 bits per byte, MSB-first) to construct
   the 128-bit AES encryption key.
4. Decrypt the ciphertext (hex-decoded from output.txt) using AES in ECB mode.
5. Strip PKCS#7 padding to reveal the plaintext flag.
"""
import sys
from Crypto.Cipher import AES

STATE_INIT = [
    0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1
]
TAPS = [63, 61, 60, 58]
CIPHERTEXT_HEX = "5fdec2e502a7c8d5951f41da4b0e0057c0b35d156e1a3e569c6cbb212a5eb8e538338e7e04fbddef0c6260a4eb758417"


def derive_key(state_init=STATE_INIT, taps=TAPS, num_bits=128) -> bytes:
    state = list(state_init)
    bits = []
    for _ in range(num_bits):
        fb = 0
        for t in taps:
            fb ^= state[t]
        popped = state.pop(0)
        state.append(fb)
        bits.append(popped)

    key_bytes = bytearray()
    for i in range(0, num_bits, 8):
        chunk = bits[i:i+8]
        val = 0
        for bit in chunk:
            val = (val << 1) | bit
        key_bytes.append(val)
    return bytes(key_bytes)


def solve(ct_hex: str = CIPHERTEXT_HEX) -> str:
    key = derive_key()
    ct = bytes.fromhex(ct_hex.strip())
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ct)
    pad_len = decrypted[-1]
    if pad_len < 16 and decrypted[-pad_len:] == bytes([pad_len]) * pad_len:
        plaintext = decrypted[:-pad_len].decode("latin1")
    else:
        plaintext = decrypted.decode("latin1", errors="ignore")
    return plaintext


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else CIPHERTEXT_HEX
    print(solve(target))
