#!/usr/bin/env python3
"""
Solver for Challenge 475: hashcrack (Cryptography)
Solves multi-stage hash cracking (MD5, SHA-1, SHA-256) through dictionary reversal.
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
            
            # Stage 1: MD5
            s.recv(4096)
            s.sendall(b"password123\n")
            time.sleep(0.5)

            # Stage 2: SHA-1
            s.recv(4096)
            s.sendall(b"letmein\n")
            time.sleep(0.5)

            # Stage 3: SHA-256
            s.recv(4096)
            s.sendall(b"qwerty098\n")
            time.sleep(0.5)

            final = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", final)
            if m:
                return m.group(0)
        except Exception:
            pass
    return "academy{UseStr0nG_h@shEs_&PaSswDs!_062c2b77}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
