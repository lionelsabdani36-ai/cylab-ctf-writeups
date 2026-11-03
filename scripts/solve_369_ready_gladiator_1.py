#!/usr/bin/env python3
"""Solver for Challenge 369 Ready Gladiator 1 (picoCTF 2023, Reverse Engineering).

CoreWars Redcode challenge where the objective is to create a warrior program
that beats the opponent 'Imp' in at least one round out of 100 rounds.
The opponent 'Imp' replicates itself linearly across the circular core buffer using
'mov 0, 1'. By deploying a classic 'Dwarf' (bomber) warrior starting at instruction 0,
the program repeatedly drops 'dat #0, #0' bombs every 4 memory addresses. When Imp's
execution pointer lands on a dat bomb, Imp's thread is terminated immediately,
yielding warrior 1 victories.

Flag: academy{1mp_1n_7h3_cr055h41r5_db62826b}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import sys
import re

HOST = "chatelaine.cylabacademy.net"
PORT = 25344
EXPECTED = "academy{1mp_1n_7h3_cr055h41r5_db62826b}"

PAYLOAD = b""";redcode
;name Dwarf
;assert 1
start add #4, bomb
mov bomb, @bomb
jmp start
bomb dat #0, #0
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
