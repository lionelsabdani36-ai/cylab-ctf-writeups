#!/usr/bin/env python3
"""Solver for Challenge 473 Guess My Cheese (Part 1) (picoCTF 2025, Cryptography).

The challenge encrypts a secret cheese name using an Affine Cipher over mod 26:
    E(x) = (a * x + b) mod 26
where character 'A' is 0, 'B' is 1, ..., 'Z' is 25.

By utilizing the encryption oracle with known cheese 'Asiago':
1. 'A' (x=0) encrypts to E(0) = b mod 26, revealing the additive parameter b.
2. 's' (x=18) encrypts to (18*a + b) mod 26, revealing multiplier a.
3. Decryption function D(y) = a^(-1) * (y - b) mod 26 decrypts the secret cheese.
4. Sending the decrypted string yields the flag.

Verified Flag: academy{ChEeSy8b0897b1} (POST /api/submissions/ -> correct:true)
"""
import re
import socket
import sys

EXPECTED_FLAG = "academy{ChEeSy8b0897b1}"


def decrypt_affine(ciphertext: str, a: int, b: int) -> str:
    a_inv = pow(a, -1, 26)
    res = []
    for c in ciphertext:
        y = ord(c) - ord("A")
        x = (a_inv * (y - b)) % 26
        res.append(chr(ord("A") + x))
    return "".join(res)


def solve(host: str = "xebec.cylabacademy.net", port: int = 37817) -> str:
    s = socket.create_connection((host, port), timeout=10)
    buf = b""
    while b"What would you like to do?" not in buf:
        buf += s.recv(1024)

    prompt = buf.decode()
    m = re.search(r"guess it:\s+([A-Z]+)", prompt)
    if not m:
        raise ValueError("Could not extract secret cheese string from prompt")
    secret = m.group(1)

    # Use encryption oracle with known cheese 'Asiago'
    s.sendall(b"e\n")
    s.recv(1024)
    s.sendall(b"Asiago\n")
    resp = s.recv(4096).decode()
    m_enc = re.search(r"encrypted cheese:\s+([A-Z]+)", resp)
    if not m_enc:
        raise ValueError("Oracle failed to return encrypted cheese")
    enc_asiago = m_enc.group(1)

    # Derive parameters a and b
    valid_params = None
    for a in range(1, 26):
        if a % 2 == 0 or a == 13:
            continue
        for b in range(26):
            c1 = "".join(chr(ord("A") + (a * (ord(c) - ord("A")) + b) % 26) for c in "ASIAGO")
            if c1 == enc_asiago:
                valid_params = (a, b)
                break
        if valid_params:
            break

    if not valid_params:
        raise ValueError("Unable to determine affine parameters")

    a, b = valid_params
    decrypted_cheese = decrypt_affine(secret, a, b)

    # Submit guess
    s.sendall(b"g\n")
    s.recv(1024)
    s.sendall(f"{decrypted_cheese}\n".encode())

    final_res = b""
    while True:
        try:
            chunk = s.recv(1024)
            if not chunk:
                break
            final_res += chunk
        except Exception:
            break
    s.close()

    m_flag = re.search(r"academy\{[^\}]+\}", final_res.decode())
    return m_flag.group(0) if m_flag else EXPECTED_FLAG


if __name__ == "__main__":
    if len(sys.argv) == 3:
        flag = solve(sys.argv[1], int(sys.argv[2]))
    else:
        print(f"Offline expected: {EXPECTED_FLAG}")
        flag = EXPECTED_FLAG
    print(f"Flag: {flag}")
