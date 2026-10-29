#!/usr/bin/env python3
"""Solver for Challenge 134 Shop (picoCTF 2021, Reverse Engineering).

Binary: Go shop (market) over netcat. Start 40 coins; Fruitful Flag costs 100.
Root cause: buy path accepts negative quantity -> price*qty subtracted from
balance, i.e. buying -10 Quiet Quiches ADDS 100 coins and inflates stock.
Exploit: buy item 0 qty -10 twice (-> 240 coins), then buy item 2 qty 1.
Server prints flag as decimal byte array; decode to ASCII.

Usage: solve_134_shop.py [host] [port]
"""
import socket
import sys
import time

HOST = "xebec.cylabacademy.net"
PORT = 28686


def recvall(s, timeout=6):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > 65536 or b"Choose an option" in out or b"Flag is" in out:
                break
    except socket.timeout:
        pass
    return out


def send(s, line):
    s.sendall((line + "\n").encode())
    time.sleep(0.7)


def solve(host=HOST, port=PORT, timeout=15):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        banner = recvall(s)
        print(banner.decode(errors="replace"))
        for cmd in ["0", "-10", "0", "-10", "2", "1"]:
            send(s, cmd)
            data = recvall(s)
            print(f">>> {cmd}\n" + data.decode(errors="replace"))
            if b"Flag is" in data:
                import re

                nums = list(map(int, re.findall(rb"\d+", data.split(b"Flag is:")[1])))
                flag = bytes(nums).decode().strip()
                print(f"FLAG: {flag}")
                return flag
        raise ValueError("flag not found in session")
    finally:
        s.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(host, port))
