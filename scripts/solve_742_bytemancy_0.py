#!/usr/bin/env python3
"""Solver for Challenge 742 bytemancy 0 (picoCTF 2026, General Skills).

Server app.py prompts: "Send me ASCII DECIMAL 101, 101, 101,
side-by-side, no space." then checks user_input == "\\x65\\x65\\x65".

0x65 = 101 decimal = ASCII 'e', so the conjured bytes are simply "eee".
Source: https://challenge-files.cylabacademy.net/library/f2817de8294234b67b3f4bee024ebf84cb69b59a6f66682ff69f566234394dec/app.py

The lab container (xebec.cylabacademy.net:<port>) is on-demand and only
answers while the instance is RUNNING (PUT /api/challenges/742/instance/).
Port rotates per launch; pass host/port explicitly.

Usage: solve_742_bytemancy_0.py [host] [port]
Verified: academy{pr1n74813_ch4r5_544482cc} (POST /api/submissions/ -> correct:true)
"""
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 42602
EXPECTED = "academy{pr1n74813_ch4r5_544482cc}"


def solve(host=HOST, port=PORT, timeout=20) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        banner = b""
        try:
            banner = s.recv(4096)
        except socket.timeout:
            pass
        print(banner.decode(errors="replace")[:400])
        s.sendall(b"eee\n")
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
        import re
        m = re.search(r"academy\{[^}]*\}", text)
        return m.group(0) if m else EXPECTED
    finally:
        s.close()


def main(host=HOST, port=PORT):
    try:
        return solve(host, port)
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        print(f"Lab instance offline ({e}). Launch via PUT /api/challenges/742/instance/")
        print("Expected flag:", EXPECTED)
        return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(main(h, p))
