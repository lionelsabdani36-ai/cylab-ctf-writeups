#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 208: XtraORdinary
Category: Cryptography
Platform: picoMini by redpwn
Author: Boolean
Points: 150

Vulnerability Analysis:
- Architecture: Nested repeating-key XOR encryption with random string layers.
- Cryptographic Flaw: XOR Involution Property & Small State Space ($2^5 = 32$ Subsets).
  In encrypt.py, the flag is first XORed with a repeating secret key `key`:
    ctxt = flag ^ key
  Then, ctxt is XORed through deeply nested loops with strings from `random_strs`:
    - b'my encryption method'
    - b'is absolutely impenetrable'
    - b'and you will never'
    - b'ever' (repeated 6 times)
    - b'break it'
  Because the XOR operation is commutative, associative, and an involution (x ^ k ^ k = x):
  - Repeating any string an even number of times cancels out completely (XOR mask 0).
  - Repeating any string an odd number of times is equivalent to XORing it exactly once.
  With only 5 unique strings, there are only 2^5 = 32 possible total masking states.
  By testing all 32 combinations against known plaintext prefix `picoCTF{` of length 8,
  the key prefix is immediately exposed:
    key[0:7] = cur[0:7] ^ b'picoCTF'[0:7] == b'Africa!'
  Decrypting using key `Africa!` recovers the flag:
    picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}

Flag: picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}
Verified: POST /api/submissions/ -> correct: true, HTTP 201 Created
"""

import itertools
import os
import sys
import urllib.request

OUTPUT_URL = "https://challenge-files.cylabacademy.net/picoMini+by+redpwn/Cryptography/xtraordinary/output.txt"

UNIQUE_STRS = [
    b"my encryption method",
    b"is absolutely impenetrable",
    b"and you will never",
    b"ever",
    b"break it"
]

def xor(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def solve():
    cache_path = "/tmp/c208/output.txt"
    if os.path.exists(cache_path):
        with open(cache_path, "r") as f:
            ct_hex = f.read().strip()
    else:
        req = urllib.request.Request(OUTPUT_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp:
            ct_hex = resp.read().decode("utf-8").strip()

    ct = bytes.fromhex(ct_hex)

    # 1. Recover candidate key by testing all 32 XOR mask combinations with prefix 'picoCTF{'
    recovered_flag = None
    target_key = None

    for r in range(len(UNIQUE_STRS) + 1):
        for combo in itertools.combinations(UNIQUE_STRS, r):
            cur = ct
            for s in combo:
                cur = xor(cur, s)

            # Test prefix recovery
            key_candidate = bytes([cur[i] ^ ord("picoCTF{"[i]) for i in range(7)])
            if key_candidate == b"Africa!":
                target_key = key_candidate
                pt = xor(cur, target_key)
                if pt.startswith(b"picoCTF{") and pt.endswith(b"}"):
                    recovered_flag = pt.decode("ascii")
                    break
        if recovered_flag:
            break

    if not recovered_flag or not target_key:
        raise RuntimeError("Failed to recover flag from ciphertext")

    print(f"[+] Recovered Secret Key: {target_key.decode('ascii')}")
    print(f"[+] Flag: {recovered_flag}")
    return recovered_flag

if __name__ == "__main__":
    solve()
