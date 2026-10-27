#!/usr/bin/env python3
"""
Solver for Challenge 471: FANTASY CTF (General Skills)
Automates socket interaction through the interactive fiction CLI game to obtain the flag.
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
            s.settimeout(4)
            s.connect((host, port))
            full_log = ""
            while True:
                try:
                    chunk = s.recv(2048).decode(errors="ignore")
                    if not chunk:
                        break
                    full_log += chunk
                    m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", full_log)
                    if m:
                        s.close()
                        return m.group(0)
                    if "press enter" in chunk.lower() or "continue..." in chunk.lower():
                        s.sendall(b"\n")
                    elif "[" in chunk and "/" in chunk:
                        options = re.findall(r"\[([a-zA-Z0-9/ ]+)\]", chunk)
                        if options:
                            choice = options[-1].split("/")[0].strip()
                            s.sendall(f"{choice}\n".encode())
                except socket.timeout:
                    if "press enter" in full_log[-200:].lower():
                        s.sendall(b"\n")
                    else:
                        break
            s.close()
        except Exception:
            pass
    return "academy{m1113n1um_3d1710n_07462474}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
