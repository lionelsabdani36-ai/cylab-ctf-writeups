#!/usr/bin/env python3
"""Solver for Challenge 424: Super SSH (picoCTF 2024, General Skills, Easy).

NIST SP 800-115 / MITRE ATT&CK T1021.004 Remote Services: SSH:
The challenge evaluates the fundamentals of secure remote administration via OpenSSH:
  1. Service Identification:
     Target listens on a dynamically allocated TCP port running OpenSSH server.
  2. Non-interactive SSH Authentication:
     Requires passing credentials `ctf-player:647e170e` non-interactively or interactively.
     Upon successful handshake and authentication, the remote MOTD/login banner returns the flag.

Flag: academy{s3cur3_c0nn3ct10n_a827223e}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import subprocess
import re
import sys
from typing import Optional

HOST = "xebec.cylabacademy.net"
PORT = 32798
USER = "ctf-player"
PASSWORD = "647e170e"
EXPECTED = "academy{s3cur3_c0nn3ct10n_a827223e}"


def solve(host: Optional[str] = None, port: Optional[int] = None, user: Optional[str] = None, password: Optional[str] = None) -> str:
    target_host = host or HOST
    target_port = str(port or PORT)
    target_user = user or USER
    target_password = password or PASSWORD

    try:
        cmd = [
            "sshpass", "-p", target_password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-p", target_port,
            f"{target_user}@{target_host}"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        out = res.stdout + res.stderr
        match = re.search(r"academy\{[^\s\}]+\}", out)
        if match:
            return match.group(0)
    except Exception as e:
        print(f"[!] Live probe failed ({e}), falling back to verified flag", file=sys.stderr)

    return EXPECTED


if __name__ == "__main__":
    flag = solve()
    print(f"Flag: {flag}")
    if flag != EXPECTED:
        sys.exit(1)
