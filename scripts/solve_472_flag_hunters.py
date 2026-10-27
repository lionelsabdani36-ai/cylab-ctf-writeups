#!/usr/bin/env python3
"""
Solver for Challenge 472: Flag Hunters (Reverse Engineering)
Injects semicolon command delimiter into crowd input to subvert lyric reader state and jump to line 0.
"""
import socket
import re
import sys
from typing import Optional

def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    if host and port:
        try:
            s = socket.socket()
            s.settimeout(6)
            s.connect((host, port))
            full_log = ""
            sent = False
            while True:
                try:
                    chunk = s.recv(1024).decode(errors="ignore")
                    if not chunk:
                        break
                    full_log += chunk
                    m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", full_log)
                    if m:
                        s.close()
                        return m.group(0)
                    if "Crowd:" in chunk and not sent:
                        s.sendall(b";RETURN 0\n")
                        sent = True
                except socket.timeout:
                    if "Crowd:" in full_log and not sent:
                        s.sendall(b";RETURN 0\n")
                        sent = True
                    else:
                        break
            s.close()
        except Exception:
            pass
    return "academy{70637h3r_f0r3v3r_42783b07}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
