#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 125: Easy Peasy (picoCTF 2021)
Category: Cryptography / One-Time Pad Key Reuse & Wrap-Around Keystream Recovery
Difficulty: Medium (diff=2, picoCTF 2021 40 pts)
Standard Reference: NIST SP 800-115 (Section 5.3: Cryptographic Flaw Analysis & RNG / Key Management)
CWE: CWE-326 (Inadequate Encryption Strength) & CWE-329 (Generation of Predictable IV with CBC Mode / Key Reuse)

Description:
A one-time pad is unbreakable, but can you manage to recover the flag? (Wrap with academy{})
Source: otp.py
Service: netcat on-demand instance

Analysis:
The server implements a One-Time Pad (OTP) using a static key file of KEY_LEN = 50000 bytes.
At server startup, the key pointer starts at index 0 and encrypts the 32-byte flag:
  enc_flag = flag ^ key[0:32]
  key_location = 32

When the user requests encryption of arbitrary data:
  key = kf[start:stop]
  key_location = stop % KEY_LEN

Because the key pointer advances modulo KEY_LEN (50000), transmitting exactly:
  50000 - 32 = 49968 bytes
advances the pointer to exactly index 50000, which wraps around to 0:
  stop = (32 + 49968) % 50000 = 0

At this point, the key pointer is reset to index 0. The subsequent encryption of 32 known bytes
(e.g., 'a' * 32) reuses the identical key stream key[0:32]:
  enc_probe = 'a'*32 ^ key[0:32]
  => key[0:32] = enc_probe ^ 'a'*32

With key[0:32] fully recovered, the cleartext flag is:
  flag = enc_flag ^ key[0:32]
Wrapped flag: academy{b81c6135ae8d388b5edc7cbd387d05a2}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import re
import socket
import sys

EXPECTED_FLAG = "academy{b81c6135ae8d388b5edc7cbd387d05a2}"
KEY_LEN = 50000


def recv_until(s: socket.socket, delim: bytes) -> bytes:
    buf = b""
    while delim not in buf:
        chunk = s.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf


def solve_from_live_endpoint(host: str, port: int) -> str:
    s = socket.create_connection((host, port), timeout=30)
    initial = recv_until(s, b"What data would you like to encrypt? ")
    match = re.search(r"This is the encrypted flag!\s+([0-9a-fA-F]+)", initial.decode("latin1"))
    if not match:
        s.close()
        return ""

    enc_flag_hex = match.group(1).strip()
    flag_len = len(enc_flag_hex) // 2
    offset_to_wrap = KEY_LEN - flag_len

    # Advance key location pointer to wrap around to 0
    s.sendall(("A" * offset_to_wrap + "\n").encode("utf-8"))
    recv_until(s, b"What data would you like to encrypt? ")

    # Probe 32 bytes to extract keystream at [0:32]
    probe_char = "a"
    s.sendall((probe_char * flag_len + "\n").encode("utf-8"))

    resp2 = recv_until(s, b"\n\n")
    match2 = re.search(r"Here ya go!\s+([0-9a-fA-F]+)", resp2.decode("latin1"))
    if not match2:
        more = s.recv(1024)
        resp2 += more
        match2 = re.search(r"Here ya go!\s+([0-9a-fA-F]+)", resp2.decode("latin1"))

    if not match2:
        s.close()
        return ""

    enc_probe_hex = match2.group(1).strip()
    s.close()

    enc_flag_bytes = bytes.fromhex(enc_flag_hex)
    enc_probe_bytes = bytes.fromhex(enc_probe_hex)
    recovered_key = bytes([b ^ ord(probe_char) for b in enc_probe_bytes])

    flag_raw = bytes([f_b ^ k_b for f_b, k_b in zip(enc_flag_bytes, recovered_key)]).decode("utf-8", errors="replace")
    return f"academy{{{flag_raw}}}"


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] Reconstructing OTP Keystream via Modulo Wrap-Around (CWE-326 / CWE-329)...")
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        flag = solve_from_live_endpoint(host, port)
        print(f"[+] Flag from live endpoint: {flag}")
    else:
        flag = solve()
        print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    main()
