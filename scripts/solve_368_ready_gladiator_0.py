#!/usr/bin/env python3
"""Solver for Challenge 368 Ready Gladiator 0 (picoCTF 2023, Reverse Engineering).

CoreWars Redcode challenge where the objective is to craft a warrior program
that always loses against the opponent 'Imp' in 100 rounds with zero ties.
In Redcode, executing an invalid opcode or 'dat #0, #0' terminates the process
immediately, resulting in an instant loss on cycle 1 while Imp continues moving.

Flag: academy{h3r0_t0_z3r0_4m1r1gh7_1c8e5812}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 32636
EXPECTED = "academy{h3r0_t0_z3r0_4m1r1gh7_1c8e5812}"

PAYLOAD = b""";redcode
;name Die
;assert 1
dat #0, #0
end
"""


def solve(host: str = HOST, port: int = PORT) -> str:
    s = socket.create_connection((host, int(port)), timeout=20)
    s.sendall(PAYLOAD)
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
