#!/usr/bin/env python3
"""
Automated Solver for Challenge 783: Trust But Verify (CyLab Security Academy)
Solves the interactive AI ethics fiction by asserting source verification,
code auditing, and independent citation cross-referencing.
"""

import socket
import time
import re
import sys

def solve(host="chatelaine.cylabacademy.net", port=31766):
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket()
    s.settimeout(10)
    s.connect((host, port))

    def recv_until_prompt(sock):
        buf = ""
        while True:
            try:
                chunk = sock.recv(1024).decode('utf-8', errors='ignore')
                if not chunk:
                    break
                buf += chunk
                if "[a/b/c]" in buf or "[a/b]" in buf or "(Press Enter to continue...)" in buf or "academy{" in buf:
                    break
            except socket.timeout:
                break
        return buf

    flag = None
    for _ in range(50):
        text = recv_until_prompt(s)
        if not text:
            break
        
        m = re.search(r"academy\{[^}]+\}", text)
        if m:
            flag = m.group(0)
            print(f"\n[+] SUCCESS! Extracted Flag: {flag}")
            break

        if "(Press Enter to continue...)" in text:
            s.sendall(b"\n")
        elif "[a/b/c]" in text:
            # Skenario 1: Verifikasi tautan sumber
            s.sendall(b"b\n")
        elif "[a/b]" in text:
            # Skenario 2/3: Periksa kode sebelum dijalankan / verifikasi mandiri
            s.sendall(b"b\n")
        else:
            s.sendall(b"\n")
        time.sleep(0.15)

    s.close()
    return flag

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "chatelaine.cylabacademy.net"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 31766
    solve(host, port)
