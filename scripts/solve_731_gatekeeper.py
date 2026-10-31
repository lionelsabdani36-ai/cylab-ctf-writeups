#!/usr/bin/env python3
"""Solver for Challenge 731 Gatekeeper (picoCTF 2026, Reverse Engineering).

The binary checks:
1. is_valid_decimal() -> atoi()
2. is_valid_hex() -> strtol(base 16)
3. Constraint: val > 999 and val <= 9999 and strlen == 3.
A decimal string cannot have length 3 while being > 999, but hex '3e8' (1000)
has length 3 and value 1000.
Upon entry of '3e8', reveal_flag() reads /flag.txt and prints characters in
reverse order, inserting the obfuscation token 'ftc_oc_ip' at every (i % 4 == 0).
Stripping 'ftc_oc_ip' and reversing the string recovers the flag.

Verified: academy{3_digit_hex_GT_999_fed7fa16} (POST /api/submissions/ -> correct:true)
"""
import socket
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 17012
EXPECTED = "academy{3_digit_hex_GT_999_fed7fa16}"


def descramble(scrambled: str) -> str:
    cleaned = scrambled.replace("ftc_oc_ip", "")
    return cleaned[::-1].strip()


def solve_interactive(host: str, port: int, timeout: int = 15) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        prompt = s.recv(1024).decode()
        s.sendall(b"3e8\n")
        resp = s.recv(4096).decode()
        if "Access granted:" in resp:
            scrambled = resp.split("Access granted:")[-1].strip()
            return descramble(scrambled)
        raise ValueError(f"Unexpected response: {resp}")
    finally:
        s.close()


if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(solve_interactive(sys.argv[1], int(sys.argv[2])))
    else:
        sample = "}61aftc_oc_ipf7deftc_oc_ipf_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{ymeftc_oc_ipdacaftc_oc_ip"
        print(descramble(sample))
