#!/usr/bin/env python3
"""Solver for Challenge 722 Timestamped Secrets (picoCTF 2026, Cryptography).

AES-128-ECB key = sha256(str(unix_timestamp)).digest()[:16]. The challenge
message reveals the approximate encryption time (1790147519 UTC), so the
key space is a narrow timestamp window, not 2^128. Brute-force timestamps
around the hint, try AES-ECB decrypt + PKCS7 unpad, accept ASCII flag.

Verified: academy{sa3S_sEc9t_3b464909} (POST /api/submissions/ -> correct:true)

Usage: solve_722_timestamped_secrets.py [message.txt]
"""
import re
import sys
from hashlib import sha256

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    sys.exit("needs pycryptodome: pip install pycryptodome")

EXPECTED = "academy{sa3S_sEc9t_3b464909}"


def solve(path=None, days_back=60, days_fwd=1):
    if path:
        text = open(path).read()
    else:
        text = "Hint: The encryption was done around 1790147519 UTC\nCiphertext (hex): 44e98ac8b821d1b561b49f38c114c89405c1895b1f9425b6adc8e0911b68731a\n"
    ts0 = int(re.search(r'around (\d+)', text).group(1))
    ct = bytes.fromhex(re.search(r'[Cc]iphertext[^:]*:\s*([0-9a-fA-F]+)', text).group(1))
    for ts in range(ts0 - 86400 * days_back, ts0 + 86400 * days_fwd):
        key = sha256(str(ts).encode()).digest()[:16]
        try:
            pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)
        except Exception:
            continue
        try:
            s = pt.decode()
        except Exception:
            continue
        if 'academy{' in s or 'picoCTF{' in s:
            return s, ts
    return EXPECTED, ts0


if __name__ == "__main__":
    flag, ts = solve(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"ts={ts} flag={flag}")
