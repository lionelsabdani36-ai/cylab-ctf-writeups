#!/usr/bin/env python3
"""
Automated Solver for Challenge 774: Perceptron Play Alpha (CyLab Security Academy)
Connects to TCP socket service, computes optimal weights for linearly separable 2D data, and extracts flag.
"""

import sys
import socket
import time
import re

def solve(host="xebec.cylabacademy.net", port=30983):
    s = socket.socket()
    s.settimeout(5)
    print(f"[*] Connecting to {host}:{port}...")
    s.connect((host, int(port)))
    time.sleep(0.5)
    s.recv(4096)
    
    # Send SET 1 1 0 (separating quadrant 3 from quadrant 1)
    print("[*] Setting optimal weights w1=1, w2=1, b=0...")
    s.sendall(b"SET 1 1 0\n")
    time.sleep(0.5)
    s.recv(4096)
    
    print("[*] Sending CHECK command...")
    s.sendall(b"CHECK\n")
    time.sleep(0.5)
    out = s.recv(4096).decode("utf-8", errors="ignore")
    print(out)
    
    match = re.search(r"academy\{[^}]+\}", out)
    if match:
        flag = match.group(0)
        print(f"[!] EXTRACTED FLAG: {flag}")
        s.close()
        return flag
    s.close()
    return None

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "xebec.cylabacademy.net"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 30983
    solve(h, p)
