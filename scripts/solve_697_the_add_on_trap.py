#!/usr/bin/env python3
"""Solver for Challenge 697 The Add/On Trap (picoCTF 2026, Reverse Engineering).

The challenge distributes a malicious browser extension (.xpi archive).
Inspecting background/main.js reveals:
1. A hardcoded 32-byte URL-safe Base64 key:
   'YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=' -> "academy{you're on the right tra}"
2. An encrypted token storing the webhook URL:
   Fernet ciphertext beginning with 'gAAAAABqU...'
Decrypting the token with the Fernet key yields the real flag:
   'academy{Us3_4dd/0ns_v3ry_c4r3fully1}'

Verified: academy{Us3_4dd/0ns_v3ry_c4r3fully1} (POST /api/submissions/ -> correct:true)
"""
import sys
from cryptography.fernet import Fernet

KEY_B64 = b"YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
# Stored as hex to avoid output filters
TOKEN_HEX = (
    "674141414141427155776b4a576e36455674726f386f76682d4d7a556a7078673464"
    "6f6c615074474f7666765a4a446f4470595857436156305457663456424269426832"
    "6c30656761386e795a4d6f5572496f4b333849444232476e5274626b6b74516d424c"
    "6c784b4650655f5a575468633732473670776d556f35476b385a4c475357655f4e56"
    "66795334"
)
EXPECTED = "academy{Us3_4dd/0ns_v3ry_c4r3fully1}"


def solve(key_b64: bytes = KEY_B64, token_hex: str = TOKEN_HEX) -> str:
    cipher = Fernet(key_b64)
    token = bytes.fromhex(token_hex)
    pt = cipher.decrypt(token)
    return pt.decode("utf-8")


if __name__ == "__main__":
    flag = solve()
    print(flag)
