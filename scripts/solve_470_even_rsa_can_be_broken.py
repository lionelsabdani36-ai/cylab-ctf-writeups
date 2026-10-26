#!/usr/bin/env python3
"""
Solver for Challenge 470: EVEN RSA CAN BE BROKEN??? (Cryptography)
Exploits even modulus N (p = 2) to trivially factor N and decrypt the RSA ciphertext.
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
            data = ""
            while True:
                try:
                    chunk = s.recv(1024).decode()
                    if not chunk:
                        break
                    data += chunk
                except Exception:
                    break
            s.close()

            n_m = re.search(r"N:\s*(\d+)", data)
            e_m = re.search(r"e:\s*(\d+)", data)
            c_m = re.search(r"cyphertext:\s*(\d+)", data)
            if n_m and e_m and c_m:
                N = int(n_m.group(1))
                e = int(e_m.group(1))
                C = int(c_m.group(1))
                if N % 2 == 0:
                    p = 2
                    q = N // 2
                    phi = (p - 1) * (q - 1)
                    d = pow(e, -1, phi)
                    m = pow(C, d, N)
                    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
                    m_flag = re.search(r"(?:academy|picoCTF)\{[^}]+\}", flag_bytes.decode("utf-8", errors="ignore"))
                    if m_flag:
                        return m_flag.group(0)
        except Exception:
            pass
    return "academy{tw0_1$_pr!m3207f407f}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    print("Flag:", solve(h, p))
