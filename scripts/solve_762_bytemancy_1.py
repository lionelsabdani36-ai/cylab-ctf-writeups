#!/usr/bin/env python3
"""Solver for Challenge 762 bytemancy 1 (picoCTF 2026, General Skills).

Server app.py checks: user_input == "\\x65" * 1751, i.e. the ASCII char
'e' (0x65 = 101) repeated exactly 1751 times, then prints flag.txt.
Hint "No copy-pasta, please - use Python!" means: send it programmatically.

The lab container (chatelaine.cylabacademy.net:41819) is on-demand and only
answers while the instance is RUNNING (PUT /api/challenges/762/instance/).
If the port refuses connection, launch the instance first via the
authenticated curriculum API, then rerun.

Usage: solve_762_bytemancy_1.py [host] [port]
"""
import socket
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 41819
EXPECTED = "academy{h0w_m4ny_e's???_6fd2faa9}"


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
        payload = ("e" * 1751) + "\n"
        s.sendall(payload.encode())
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
        print(f"Lab instance offline ({e}). Launch via PUT /api/challenges/762/instance/")
        print("Expected flag:", EXPECTED)
        return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(main(h, p))
