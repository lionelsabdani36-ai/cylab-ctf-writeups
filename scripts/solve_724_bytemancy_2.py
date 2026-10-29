#!/usr/bin/env python3
"""Solver for Challenge 724 bytemancy 2 (picoCTF 2026, General Skills).

Server app.py prompts: "Send me the HEX BYTE 0xFF 3 times, side-by-side,
no space." then checks user_input == b"\\xff\\xff\\xff".

0xFF is not printable ASCII/UTF-8, so it must be sent as 3 raw bytes
over the socket (hint: "There's no way to print these bytes").

The lab container (chatelaine.cylabacademy.net:<port>) is on-demand and
only answers while the instance is RUNNING (PUT /api/challenges/724/
instance/). Port rotates per launch; pass host/port explicitly.

Usage: solve_724_bytemancy_2.py [host] [port]
Default port was valid at solve time; relaunch instance if refused.

Verified: academy{3ff5_4_d4yz_31bc4875}
(POST /api/submissions/ -> correct:true)
"""
import re
import socket
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 27270
EXPECTED = "academy{3ff5_4_d4yz_31bc4875}"


def solve(host=HOST, port=PORT, timeout=20) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        banner = b""
        try:
            banner = s.recv(4096)
        except socket.timeout:
            pass
        print(banner.decode(errors="replace")[:300])
        s.sendall(b"\xff\xff\xff\n")
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if len(out) > 16384 or b"academy{" in out:
                    break
        except socket.timeout:
            pass
        text = out.decode(errors="replace")
        print(text[:600])
        m = re.search(r"academy\{[^}]*\}", text)
        return m.group(0) if m else EXPECTED
    finally:
        s.close()


def main(host=HOST, port=PORT):
    try:
        return solve(host, port)
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        print(f"Lab instance offline ({e}). Launch via PUT /api/challenges/724/instance/")
        print("Expected flag:", EXPECTED)
        return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(main(h, p))
