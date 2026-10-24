#!/usr/bin/env python3
"""
Automated Solver for Challenge 773: Perceptron Play 1D Alpha
Connects via socket, sets optimal w=1 b=-1, and triggers CHECK.
"""
import socket
import sys

def solve(host="xebec.cylabacademy.net", port=12641):
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, int(port)))
    s.recv(4096)
    s.sendall(b"SET 1 -1\n")
    s.recv(4096)
    s.sendall(b"CHECK\n")
    out = s.recv(4096).decode("utf-8", errors="ignore")
    print(out)
    s.close()

if __name__ == "__main__":
    solve()
