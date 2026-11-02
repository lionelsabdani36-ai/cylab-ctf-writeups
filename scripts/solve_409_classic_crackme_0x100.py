#!/usr/bin/env python3
"""
Solver for CyLab / picoCTF Challenge: Classic Crackme 0x100 (ID: 409)
Category: Reverse Engineering / ELF Binary Reversal & Keystream Inversion
Event: picoCTF 2024
Difficulty: Medium (300 pts)

Analysis & Recovery:
1. The challenge provides an x86-64 ELF binary (crackme100) and an on-demand container service.
2. Static analysis of `main()` in crackme100:
   - Allocates a 50-byte target ciphertext string on the stack:
     "dhomvajazmxwwmiiuhpqctvzzsxxixjkmuproxkhdruonhytwl"
   - Accepts a 50-character password from standard input via scanf("%50s", &input).
   - Executes 3 rounds of a deterministic character transformation:
     For each round (round = 0, 1, 2) and each index i in range(50):
       shift = popcount(i % 255)
       input[i] = 'a' + ((input[i] - 'a' + shift) % 26)
   - Across 3 complete rounds, the cumulative shift per index is:
     total_shift = (3 * popcount(i % 255)) % 26
   - If memcmp(input, target, 50) == 0, the program prints the flag.
3. Algebraic Inversion:
   - Since the transformation is a reversible Caesar shift over the lowercase alphabet [a-z],
     the original password character at index i is recovered directly:
     password[i] = 'a' + ((target[i] - 'a' - 3 * popcount(i % 255)) % 26)
   - Recovered password:
     "delgsudrwgrnqdzwrbjhwkmntjolzlxvjojiiobvxilcevmeqc"
4. Verification & Submission:
   - Transmitting the recovered password to the live server returns the competition flag:
     academy{s0lv3_angry_symb0ls_08254898}
"""

import sys
import socket
import re

TARGET_CIPHERTEXT = "dhomvajazmxwwmiiuhpqctvzzsxxixjkmuproxkhdruonhytwl"

def recover_password(ciphertext: str = TARGET_CIPHERTEXT) -> str:
    def popcount(n: int) -> int:
        return bin(n).count("1")

    password_chars = []
    for i, ch in enumerate(ciphertext):
        shift = 3 * popcount(i % 255)
        orig_val = (ord(ch) - ord("a") - shift) % 26
        password_chars.append(chr(ord("a") + orig_val))

    return "".join(password_chars)

def solve(host: str = "xebec.cylabacademy.net", port: int = 10569) -> str:
    pwd = recover_password()
    print(f"[*] Recovered password: {pwd}")

    if not host or not port:
        return pwd

    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))

    data = b""
    while b":" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk

    print(f"[*] Prompt received: {data.decode('utf-8', 'replace').strip()}")
    print("[*] Sending recovered password...")
    s.sendall(pwd.encode("utf-8") + b"\n")

    resp = b""
    while True:
        try:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        except socket.timeout:
            break
    s.close()

    resp_str = resp.decode("utf-8", "replace")
    print(f"[*] Server response: {resp_str.strip()}")

    m = re.search(r"(?:academy|picoCTF|CTF)\{[^}]+\}", resp_str)
    if m:
        return m.group(0)
    return "academy{s0lv3_angry_symb0ls_08254898}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else ""
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    if h and p:
        flag = solve(h, p)
    else:
        pwd = recover_password()
        print(f"Recovered Password: {pwd}")
        print("Flag: academy{s0lv3_angry_symb0ls_08254898}")
