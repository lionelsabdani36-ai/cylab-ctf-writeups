#!/usr/bin/env python3
"""Solver for Challenge 428 - weirdSnake (picoCTF 2024, Reverse Engineering).

The challenge presents Python 3.11/3.12 bytecode disassembly ('snake') generated via `dis.dis()`.
Static bytecode deconstruction:
1. input_list is initialized with 40 integers:
   [21, 60, 43, 11, 86, 25, 38, 49, 33, 3, 0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 43, 59, 121, 93, 1, 17, 58, 126, 95, 78]
2. String concatenation sequence for key_str:
   - key_str = 'J'
   - key_str = '_' + key_str ('_J')
   - key_str = key_str + 'o' ('_Jo')
   - key_str = key_str + '3' ('_Jo3')
   - key_str = 't' + key_str ('t_Jo3')
3. key_list = [ord(c) for c in key_str]
   Expanded iteratively via key_list.extend(key_list) until len(key_list) >= len(input_list).
4. XOR decryption:
   result = [a ^ b for a, b in zip(input_list, key_list)]
   result_text = ''.join(map(chr, result))
5. Flag recovered:
   academy{N0t_sO_coNfus1ng_sn@ke_d322ee40}

Verified: academy{N0t_sO_coNfus1ng_sn@ke_d322ee40} (POST /api/submissions/ -> correct:true, HTTP 201)
"""
import os
import sys
import urllib.request

SNAKE_URL = "https://challenge-files.cylabacademy.net/library/95d371d7d45cc419952a85a855c8702bc8ebb6be6f9f8de65dde151315a5b484/snake"
EXPECTED_FLAG = "academy{N0t_sO_coNfus1ng_sn@ke_d322ee40}"


def solve(snake_path: str = "snake") -> str:
    if not os.path.exists(snake_path):
        print(f"[*] Downloading {SNAKE_URL}...")
        urllib.request.urlretrieve(SNAKE_URL, snake_path)

    input_list = [
        21, 60, 43, 11, 86, 25, 38, 49, 33, 3,
        0, 0, 57, 32, 108, 23, 48, 4, 9, 70,
        7, 110, 36, 8, 108, 7, 49, 10, 4, 86,
        43, 59, 121, 93, 1, 17, 58, 126, 95, 78
    ]

    key_str = "J"
    key_str = "_" + key_str
    key_str = key_str + "o"
    key_str = key_str + "3"
    key_str = "t" + key_str

    key_list = [ord(char) for char in key_str]

    while len(key_list) < len(input_list):
        key_list.extend(key_list)

    result = [a ^ b for a, b in zip(input_list, key_list)]
    result_text = "".join(map(chr, result))

    print(f"[+] Reconstructed Flag: {result_text}")
    assert result_text == EXPECTED_FLAG, f"Flag mismatch: {result_text} vs {EXPECTED_FLAG}"
    return result_text


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/c428/snake" if os.path.exists("/tmp/c428/snake") else "snake"
    solve(target)
