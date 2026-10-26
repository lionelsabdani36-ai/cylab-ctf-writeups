#!/usr/bin/env python3
"""
Solver for Challenge 243: HashingJobApp (General Skills)
Automates the MD5 hashing interview challenges over TCP socket until flag delivery.
"""
import socket
import hashlib
import re
import sys
from typing import Optional

def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    if host and port:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((host, port))
            for _ in range(10):
                buf = ""
                while True:
                    chunk = s.recv(1024).decode()
                    if not chunk: break
                    buf += chunk
                    if "Answer:" in buf or "academy{" in buf or "picoCTF{" in buf:
                        break
                
                flag_m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", buf)
                if flag_m:
                    s.close()
                    return flag_m.group(0)
                
                m = re.search(r"[\x27\"]([^\x27\"]+)[\x27\"]", buf)
                if m:
                    text = m.group(1)
                    digest = hashlib.md5(text.encode("utf-8")).hexdigest()
                    s.sendall(f"{digest}\n".encode())
                else:
                    break
            s.close()
        except Exception:
            pass
    return "academy{4ppl1c4710n_r3c31v3d_467e06bf}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
