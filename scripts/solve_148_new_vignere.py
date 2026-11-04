#!/usr/bin/env python3
"""Solver for Challenge 148: New Vignere (picoCTF 2021, Cryptography, Hard/Medium).

NIST SP 800-115 / RFC 4949 Cryptanalysis of Polyalphabetic Substitution:
The challenge implements a 16-character alphabet Vigenere cipher layered over a base16 (nibble) encoding:
  1. Base16 Encoding Structure:
     Each character of the hex flag is converted into an 8-bit binary string and split into two 4-bit nibbles.
     Each nibble (0-15) indexes into ALPHABET = 'abcdefghijklmnop'.
     Hex digits '0'-'9' (0x30..0x39) produce high nibble 3 ('d') and low nibble 0..9 ('a'..'j').
     Hex digits 'a'-'f' (0x61..0x66) produce high nibble 6 ('g') and low nibble 1..6 ('b'..'g').
     Therefore, every even-indexed base16 character MUST be either 'd' or 'g'.
  2. Key Space Constraint & Shift Reversal:
     The key consists only of lowercase letters in ALPHABET with length < 15.
     The shift operation is defined as: c_enc = ALPHABET[(c_plain + k) % 16].
     Its reciprocal unshift operation is: c_plain = ALPHABET[(c_enc - k) % 16].
  3. Key Derivation via Nibble Filtering:
     For a candidate key length L in [1..14], every character k_j at position j must satisfy:
     For all even indices i where i % L == j, unshift(enc[i], k_j) in {'d', 'g'}.
     For L = 9, exactly one key combination yields valid hex characters across the entire decrypted text.

Key recovered: bickhknij
Flag: academy{468293b06253c715005873e333d98dbc}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import string
import itertools
import sys
from typing import Optional

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

CIPHERTEXT = "emfakcakmklfajnnlpekfpkndlmildnmnnljenfckbalpglfnknaonebfcnodkpe"


def b16_decode(enc_pair: str) -> str:
    n1 = ALPHABET.index(enc_pair[0])
    n2 = ALPHABET.index(enc_pair[1])
    val = (n1 << 4) | n2
    return chr(val)


def unshift(c: str, k: str) -> str:
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]


def solve(enc: str = CIPHERTEXT) -> Optional[str]:
    # Test key lengths from 1 to 14
    for key_len in range(1, 15):
        possible_keys = []
        for k_pos in range(key_len):
            candidates = []
            for k_char in ALPHABET:
                valid = True
                for idx in range(k_pos, len(enc), key_len):
                    b16_char = unshift(enc[idx], k_char)
                    if idx % 2 == 0:
                        # High nibble must be 'd' or 'g'
                        if b16_char not in ("d", "g"):
                            valid = False
                            break
                if valid:
                    candidates.append(k_char)
            possible_keys.append(candidates)

        if not all(len(c) > 0 for c in possible_keys):
            continue

        for k_tuple in itertools.product(*possible_keys):
            k = "".join(k_tuple)
            b16 = ""
            for i, c in enumerate(enc):
                b16 += unshift(c, k[i % len(k)])

            plain = ""
            valid_flag = True
            for i in range(0, len(b16), 2):
                pair = b16[i : i + 2]
                ch = b16_decode(pair)
                if ch not in "abcdef0123456789":
                    valid_flag = False
                    break
                plain += ch

            if valid_flag and len(plain) == len(enc) // 2:
                return f"academy{{{plain}}}"
    return None


if __name__ == "__main__":
    target_enc = sys.argv[1] if len(sys.argv) > 1 else CIPHERTEXT
    flag = solve(target_enc)
    if flag:
        print("Flag:", flag)
    else:
        print("Failed to recover flag")
