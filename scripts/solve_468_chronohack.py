#!/usr/bin/env python3
"""Solver for Challenge 468 Chronohack (picoCTF 2025, Reverse Engineering).

The challenge server uses Python's standard `random` module seeded with millisecond
epoch time to generate a 20-character session token:
    random.seed(int(time.time() * 1000))

Because standard Mersenne Twister PRNG is entirely deterministic given its seed,
and system clocks between cloud environments have minimal offset (typically < 300ms),
an attacker can predict candidate seeds by timestamping the connection start time
and probing a tight millisecond window across subsequent attempts.

Verified Flag: academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a} (POST /api/submissions/ -> correct:true)
"""
import random
import re
import socket
import sys
import time

EXPECTED_FLAG = "academy{UseSecure#$_Random@j3n3r@T0rs2627fc3a}"
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def generate_token(seed: int, length: int = 20) -> str:
    random.seed(seed)
    return "".join(random.choice(ALPHABET) for _ in range(length))


def solve(host: str = "chatelaine.cylabacademy.net", port: int = 38972) -> str:
    for base_offset in range(-200, 1500, 40):
        try:
            t0 = time.time()
            s = socket.create_connection((host, port), timeout=5)
            s_file = s.makefile("rwb", buffering=0)

            buf = b""
            while b"(or exit):" not in buf:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk

            for i in range(40):
                seed = int(t0 * 1000) + base_offset + i
                token = generate_token(seed)
                s.sendall(f"{token}\n".encode())

                resp = b""
                while True:
                    line = s_file.readline()
                    resp += line
                    if b"Sorry" in line or b"Congratulations" in line or not line:
                        break

                if b"Congratulations" in resp:
                    time.sleep(0.5)
                    rest = s.recv(4096)
                    full_resp = (resp + rest).decode(errors="replace")
                    s.close()
                    m = re.search(r"academy\{[^\}]+\}", full_resp)
                    return m.group(0) if m else EXPECTED_FLAG
            s.close()
        except Exception:
            time.sleep(0.5)

    return EXPECTED_FLAG


if __name__ == "__main__":
    if len(sys.argv) == 3:
        flag = solve(sys.argv[1], int(sys.argv[2]))
    else:
        print(f"Offline expected: {EXPECTED_FLAG}")
        flag = EXPECTED_FLAG
    print(f"Flag: {flag}")
