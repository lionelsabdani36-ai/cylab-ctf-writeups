#!/usr/bin/env python3
"""Solver for Challenge 761 Bypass Me (picoCTF 2026, Reverse Engineering).

SSH lab on-demand (PUT /api/challenges/761/instance/): setuid-root
`bypassme.bin` (not stripped, with debug info). `main` decodes an
11-byte XOR-0xAA password at startup, reads user input via fgets,
strips the newline, filters non-alpha via sanitize(), then strcmp()s the
RAW input against the decoded secret. Match -> setuid root reads
`./../root/flag.txt` and prints it.

Key reversing details (objdump -d -M intel):
- QWORD [rbp-0x13] = 0xc9cff9d8cfdadff9 (LE bytes f9 df da cf d8 f9 cf c9)
- DWORD [rbp-0x0c] = 0xcfd8dfc9 overwrites the last QWORD byte with the
  SAME value 0xc9, then contributes df d8 cf -> 11 unique bytes total.
- Loop bound `cmp rax,0xa; jbe` reads indices 0..10 only; output[11]=0.
- Plaintext = bytes([b ^ 0xAA]) = "SuperSecure" (NOT "SuperSeccure":
  a naive 12-byte decode keeps a phantom 12th byte that the binary never
  reads, and misorders the DWORD overlap).

PTY pitfall: send the password over `ssh -T` with piped stdin (no tty
translation issues) instead of driving an interactive pty.

Usage: solve_761_bypass_me.py [host] [port] [ssh-password]
Verified: academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda} (POST /api/submissions/ -> correct:true)
"""
import re
import subprocess
import sys

HOST = "chatelaine.cylabacademy.net"
PORT = 10351
PASSWORD = "a630e1f8"
EXPECTED = "academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}"

FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")

# 11 unique encoded bytes reconstructed from the QWORD+DWORD overlap.
ENC = bytes.fromhex("f9dfdacfd8f9cfc9dfd8cf")


def decode() -> str:
    return bytes(b ^ 0xAA for b in ENC).decode()


def solve(host: str = HOST, port: int = PORT, password: str = PASSWORD,
          timeout: int = 60) -> str:
    secret = decode()
    assert secret == "SuperSecure", secret
    cmd = ["sshpass", "-p", password, "ssh", "-T",
           "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=15",
           "-p", str(port), "ctf-player@%s" % host, "./bypassme.bin"]
    proc = subprocess.run(cmd, input=(secret + "\n").encode(),
                          capture_output=True, timeout=timeout)
    out = proc.stdout.decode(errors="replace")
    m = FLAG_RE.search(out)
    if not m:
        raise ValueError("flag not in binary output: %r" % out[-500:])
    print("password:", secret)
    print("flag:", m.group(0))
    assert m.group(0) == EXPECTED, m.group(0)
    return EXPECTED


if __name__ == "__main__":
    a = sys.argv[1:]
    print(solve(a[0] if len(a) > 0 else HOST,
                int(a[1]) if len(a) > 1 else PORT,
                a[2] if len(a) > 2 else PASSWORD))
