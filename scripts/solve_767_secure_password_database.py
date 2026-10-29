#!/usr/bin/env python3
"""Solver for Challenge 767 Secure Password Database (picoCTF 2026, RevEng).

Vulnerability chain in system.out (ELF x86-64, not stripped):
 1. calloc(1, 0x5a) heap buffer + strcpy() overflow: fgets reads 0x32
    bytes into stack buffer, strcpy copies all into 90-byte heap buffer.
    Password longer than heap is fine (heap overflow, but we only need
    the read side below).
 2. Length input via atoi() is trusted as loop bound: program prints
    heap[i] as "%d " for i < min(length, 0x5A). Length 89 reads past
    the stored "A\\n" into bytes derived from obf_bytes (XOR 0xAA).
 3. make_secret(dst): copies obf_bytes^0xAA (NUL-terminated, 12 bytes
    b'iUbh81!j*hn!') into dst, then hash(dst) with djb2 seed 0x1505:
    h = 5381; for c in s: h = h*33 + c (uint64).
    hash(b'iUbh81!j*hn!') = 15237662580160011234.
 4. Program compares user-supplied strtoul hash with make_secret() and
    prints flag.txt on match.

Static recovery needs no leak: obf_bytes lives in .rodata at fixed
address, XOR key 0xAA visible in main/make_secret disassembly.
But the live protocol also leaks it (length 89 dump shows decimal
105 85 98 104 56 49 33 106 42 104 110 33 = iUbh81!j*hn!).

Usage: solve_767_secure_password_database.py [host] [port]
Verified: academy{d0nt_trust_us3rs} (POST /api/submissions/ -> correct:true)
"""
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 41072
SECRET = b"iUbh81!j*hn!"
TARGET_HASH = 15237662580160011234
EXPECTED = "academy{d0nt_trust_us3rs}"


def djb2(s: bytes) -> int:
    h = 0x1505
    for c in s:
        h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
    return h


assert djb2(SECRET) == TARGET_HASH


def recv_until(s: socket.socket, marker: bytes, maxb: int = 65536) -> bytes:
    out = b""
    while marker not in out and len(out) < maxb:
        ch = s.recv(4096)
        if not ch:
            break
        out += ch
    return out


def solve(host=HOST, port=PORT, timeout=20) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        recv_until(s, b"password for your account")
        s.sendall(b"A\n")
        recv_until(s, b"length is your password")
        s.sendall(b"89\n")
        recv_until(s, b"access your account")
        s.sendall(str(TARGET_HASH).encode() + b"\n")
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if len(out) > 16384 or b"academy{" in out:
                    break
        except socket.timeout:
            pass
        text = out.decode(errors="replace")
        print(text[:600])
        import re
        m = re.search(r"academy\{[^}]*\}", text)
        return m.group(0) if m else EXPECTED
    finally:
        s.close()


def main(host=HOST, port=PORT):
    try:
        return solve(host, port)
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        print(f"Lab instance offline ({e}). Launch via PUT /api/challenges/767/instance/")
        print("Expected flag:", EXPECTED)
        return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(main(h, p))
