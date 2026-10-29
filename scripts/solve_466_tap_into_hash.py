#!/usr/bin/env python3
"""Solver for Challenge 466 Tap into Hash (picoCTF 2025, Reverse Engineering).

The bundle file enc_flag ships BOTH the secret key and the ciphertext:
  Key: b'...'                       (32-byte random token -> AES input block)
  Encrypted Blockchain: b'...'      (384 bytes = 24 blocks of 16)

encrypt() inserts the flag into a block-hash chain string, PKCS7-pads, then
XORs every 16-byte block with sha256(key).digest() — note xor_bytes() zips
key_hash (32 bytes) against ONE 16-byte block, so only key_hash[:16] is ever
used. Decrypt = re-XOR each block with sha256(key).digest()[:16], strip
PKCS7, read academy{...} embedded mid-chain.

Recovered locally: academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}
(pending POST /api/submissions/ — session expired, re-submit with fresh cookie)

Usage: solve_466_tap_into_hash.py [enc_flag]
"""
import hashlib
import re
import sys

EXPECTED = "academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}"


def solve(path: str = "enc_flag") -> str:
    raw = open(path).read()
    key = eval(re.search(r"Key: (b'.*')", raw).group(1))
    enc = eval(re.search(r"Encrypted Blockchain: (b'.*')", raw, re.S).group(1))
    k16 = hashlib.sha256(key).digest()[:16]
    pt = b"".join(
        bytes(x ^ y for x, y in zip(enc[i:i + 16], k16))
        for i in range(0, len(enc), 16)
    )
    s = pt[:-pt[-1]].decode()
    i = s.find("academy{")
    return s[i:s.find("}", i) + 1]


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "enc_flag"))
