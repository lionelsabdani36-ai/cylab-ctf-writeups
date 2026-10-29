#!/usr/bin/env python3
"""Solver for Challenge 730 bytemancy 3 (picoCTF 2026, General Skills).

Server app.py names 3 random procedures from spellbook
(ember_sigil, glyph_conflux, astral_spark, binding_word) and expects
each procedure's 4-byte address in raw little-endian form (p32).

Symbol addresses are static (non-PIE 32-bit ELF, readelf -h: Type EXEC):
  ember_sigil   0x08049156
  glyph_conflux 0x08049176
  astral_spark  0x08049199
  binding_word  0x080491b7
Recovered via `nm spellbook` / `objdump -t spellbook`.

Protocol: read_exact_bytes(4) per round; the server peeks and discards
one trailing newline, so send exactly 4 raw bytes per answer with NO
newline between rounds... in practice sending p32(addr) + b"\\n" also
works because the server strips a single trailing newline when more
bytes are immediately available. This solver sends bare 4 bytes then
reads the next prompt, which is race-free.

The lab container (chatelaine.cylabacademy.net:<port>) is on-demand and
only answers while the instance is RUNNING (PUT /api/challenges/730/
instance/). Port rotates per launch; pass host/port explicitly.

Usage: solve_730_bytemancy_3.py [host] [port]

Verified: academy{0bjdump_m4g1c_c79394e0}
(POST /api/submissions/ -> correct:true)
"""
import re
import socket
import struct
import sys

HOST = "xebec.cylabacademy.net"
PORT = 23788  # rotates per launch; pass host/port explicitly
EXPECTED = "academy{0bjdump_m4g1c_c79394e0}"

ADDR = {
    "ember_sigil": 0x08049156,
    "glyph_conflux": 0x08049176,
    "astral_spark": 0x08049199,
    "binding_word": 0x080491B7,
}


def recv_until(s, marker=b"==> ", timeout=15, limit=65536):
    s.settimeout(timeout)
    out = b""
    try:
        while marker not in out:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > limit:
                break
    except socket.timeout:
        pass
    return out


def solve(host=HOST, port=PORT, timeout=20) -> str:
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        data = recv_until(s, b"==>", timeout)
        for rnd in range(3):
            text = data.decode(errors="replace")
            m = re.search(r"procedure '([a-z_]+)'", text)
            if not m:
                raise ValueError(f"symbol not found in prompt: {text[-300:]!r}")
            sym = m.group(1)
            s.sendall(struct.pack("<I", ADDR[sym]))
            data = recv_until(s, b"==>" if rnd < 2 else b"academy{", timeout)
            if b"academy{" in data:
                break
        text = data.decode(errors="replace")
        print(text[-600:])
        m = re.search(r"academy\{[^}]*\}", text)
        if not m:  # flag may arrive after a final recv
            rest = recv_until(s, b"}", 10)
            m = re.search(r"academy\{[^}]*\}", text + rest.decode(errors="replace"))
        if not m:
            raise ValueError("flag not found in server output")
        return m.group(0)
    finally:
        s.close()


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    print(solve(h, p))
