#!/usr/bin/env python3
"""Solver for Challenge 384 useless (picoCTF 2023, General Skills).

Linux environment exploration challenge where a basic arithmetic bash script
in the user's home directory suggests reading documentation or manual pages.
Querying the system man page (`man useless`) reveals the manual entry containing
the competition flag under the AUTHORS section.

Flag: academy{us3l3ss_ch4ll3ng3_3xpl0it3d_4318}
Verified: POST /api/submissions/ -> correct: true
"""
import paramiko
import sys
import re

HOST = "chatelaine.cylabacademy.net"
PORT = 39388
USER = "picoplayer"
PASS = "password"
EXPECTED = "academy{us3l3ss_ch4ll3ng3_3xpl0it3d_4318}"


def solve(host: str = HOST, port: int = PORT, user: str = USER, password: str = PASS) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password, timeout=15)
        stdin, stdout, stderr = client.exec_command("man useless")
        out = stdout.read().decode(errors="replace")
    finally:
        client.close()

    m = re.search(r"academy\{[^\}]+\}", out)
    if m:
        return m.group(0)
    raise ValueError(f"Flag not found in manual output: {out[:300]}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    flag = solve(host, port)
    print("Flag:", flag)
    assert flag == EXPECTED
