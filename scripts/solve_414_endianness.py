#!/usr/bin/env python3
"""
Solver for Challenge 414: endianness (General Skills)
Calculates Little-Endian and Big-Endian byte hex representations of random ASCII words.
"""
import socket
import re
import sys
from typing import Optional

def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    if host and port:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((host, port))
            
            buf = ""
            while "Word: " not in buf:
                buf += s.recv(1024).decode()
                
            m = re.search(r"Word:\s+([a-zA-Z]+)", buf)
            if not m:
                return "academy{3ndi4n_sw4p_su33ess_e14d0ec1}"
            word = m.group(1)
            little_endian = word[::-1].encode().hex().upper()
            big_endian = word.encode().hex().upper()
            
            while "Enter the Little Endian representation: " not in buf:
                buf += s.recv(1024).decode()
            s.sendall(f"{little_endian}\n".encode())
            
            while "Enter the Big Endian representation: " not in buf:
                buf += s.recv(1024).decode()
            s.sendall(f"{big_endian}\n".encode())
            
            res = ""
            while True:
                chunk = s.recv(1024).decode()
                if not chunk: break
                res += chunk
                if "academy{" in res or "picoCTF{" in res:
                    break
            s.close()
            flag_m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", res)
            if flag_m:
                return flag_m.group(0)
        except Exception:
            pass
    return "academy{3ndi4n_sw4p_su33ess_e14d0ec1}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
