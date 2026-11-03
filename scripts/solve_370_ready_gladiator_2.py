#!/usr/bin/env python3
"""Solver for Challenge 370 Ready Gladiator 2 (picoCTF 2023, Reverse Engineering).

CoreWars Redcode challenge where the objective is to craft an invincible warrior
program that defeats the opponent 'Imp' in all 100 consecutive rounds (100-0 sweep).
The opponent 'Imp' uses 'mov 0, 1' to sequentially replicate itself across memory.
By utilizing an Imp-Gate mechanism with pre-decrement addressing ('jmp 0, <-2'),
the warrior creates a self-loop that continuously decrements the memory location
immediately behind it. When the propagating Imp thread steps into this decremented
instruction, the opcode modification neutralizes the Imp's copy instruction or kills
its process pointer, resulting in 100 wins and 0 ties.

Flag: academy{d3m0n_3xpung3r_2e26bfb2}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import sys
import re

HOST = "xebec.cylabacademy.net"
PORT = 40754
EXPECTED = "academy{d3m0n_3xpung3r_2e26bfb2}"

PAYLOAD = b""";redcode
;name Imp Killer
;assert 1
jmp 0, <-2
end
"""


def solve(host: str = HOST, port: int = PORT) -> str:
    s = socket.create_connection((host, int(port)), timeout=20)
    try:
        s.sendall(PAYLOAD)
        data = b""
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
    m = re.search(r"academy\{[^\}]+\}", text)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in output: {text[:300]}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    flag = solve(host, port)
    print("Flag:", flag)
    assert flag == EXPECTED
