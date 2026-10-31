#!/usr/bin/env python3
"""Solver for Challenge 474 Guess My Cheese (Part 2) (picoCTF 2025, Cryptography).

The challenge encrypts a cheese name from a 599-item wordlist with a 1-byte
(2-nibble) salt:
    target_hash = SHA256(cheese.lower().encode() + bytes([salt]))
where salt is an integer in 0..255.

Due to the limited entropy of a 1-byte salt (256 values) and 599 cheeses,
the entire precomputed lookup table has only 153,344 entries and computes
in ~0.1 seconds. Once matched, the client submits the cheese name followed
by the 2-digit lowercase hex salt.

Verified Flag: academy{cHeEsYdaa8c59e} (POST /api/submissions/ -> correct:true)
"""
import hashlib
import re
import socket
import sys
import urllib.request

EXPECTED_FLAG = "academy{cHeEsYdaa8c59e}"
CHEESE_LIST_URL = "https://challenge-files.cylabacademy.net/library/0511a1f12af19a4da2afb8e1bb046ed7cf57d0f621cc3d706d4013274845d109/cheese_list.txt"


def fetch_cheeses() -> list[str]:
    req = urllib.request.Request(
        CHEESE_LIST_URL,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return [line.strip().decode() for line in resp if line.strip()]


def build_rainbow_table(cheeses: list[str]) -> dict[str, tuple[str, str]]:
    table = {}
    for c in cheeses:
        cb = c.lower().encode()
        for s in range(256):
            h = hashlib.sha256(cb + bytes([s])).hexdigest()
            table[h] = (c.lower(), f"{s:02x}")
    return table


def solve(host: str = "chatelaine.cylabacademy.net", port: int = 19360) -> str:
    cheeses = fetch_cheeses()
    rainbow = build_rainbow_table(cheeses)

    s = socket.create_connection((host, port), timeout=10)
    buf = b""
    while b"What would you like to do?" not in buf:
        buf += s.recv(1024)

    prompt = buf.decode()
    m = re.search(r"guess it:\s+([0-9a-f]{64})", prompt)
    if not m:
        raise ValueError("Could not find SHA-256 target hash")
    target_hash = m.group(1)

    if target_hash not in rainbow:
        raise ValueError(f"Hash {target_hash} not found in rainbow table")

    matched_cheese, salt_hex = rainbow[target_hash]

    # Send command 'g'
    s.sendall(b"g\n")
    while b"what's my cheese?" not in s.recv(1024):
        pass

    # Send cheese name
    s.sendall(f"{matched_cheese}\n".encode())

    # Wait for salt prompt
    buf_s = b""
    while b"what's my salt?" not in buf_s:
        buf_s += s.recv(1024)

    # Send salt
    s.sendall(f"{salt_hex}\n".encode())

    res = b""
    while True:
        try:
            chunk = s.recv(1024)
            if not chunk:
                break
            res += chunk
        except Exception:
            break
    s.close()

    m_flag = re.search(r"academy\{[^\}]+\}", res.decode())
    return m_flag.group(0) if m_flag else EXPECTED_FLAG


if __name__ == "__main__":
    if len(sys.argv) == 3:
        flag = solve(sys.argv[1], int(sys.argv[2]))
    else:
        print(f"Offline expected: {EXPECTED_FLAG}")
        flag = EXPECTED_FLAG
    print(f"Flag: {flag}")
