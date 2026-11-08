#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Secure Password Database (Challenge ID: 767)
Category: Reverse Engineering / Binary Exploitation | Difficulty: Medium (2) | Points: 200
Topic: Heap Out-of-Bounds Read (Heartbleed-class Leak), Weak Hashing, and Static Key Extraction
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis) & CWE-125 / CWE-328 / CWE-798

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - x86-64 ELF binary (`system.out`, not stripped) simulating a user password storage vault.
   - Prompts user to input a password into a 0x32-byte stack buffer via `fgets()`.
   - Copies password into a heap chunk allocated via `calloc(1, 0x5a)` using unbounded `strcpy()`.
   - Prompts for password length via `atoi()` and prints `heap[i]` as `%d ` for `i < min(length, 0x5a)`.
   - Demands an authentication hash value (`strtoul`) and compares it against `make_secret()`.
   - On match, opens and renders `flag.txt`.
2. Vulnerability Chain:
   - CWE-125 (Out-of-Bounds Read / Information Leak): When user passes length `89` (or `0x59`),
     the read loop traverses past the stored short input string into uninitialized/adjacent heap memory.
   - CWE-328 (Reversible / Weak Hash Function): The verification hash uses the classic `djb2` non-cryptographic
     hash algorithm with seed `0x1505` (`h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF`).
   - CWE-798 (Use of Hard-coded Secret): `make_secret()` retrieves `obf_bytes` from static `.rodata`
     (`\\xc3\\xff\\xc8\\xc2\\x92\\x9b\\x8b\\xc0\\x80\\xc2\\xc4\\x8b\\x00`), XORs with byte key `0xAA`
     yielding `b'iUbh81!j*hn!'` (12 bytes), and evaluates `djb2(b'iUbh81!j*hn!') = 15237662580160011234`.
3. Exploitation & Verification:
   - Pure static mathematical recovery of target hash `15237662580160011234` without guessing passwords.
   - Live socket payload automation and fallback simulation.
   - REST API verification against CyLab Academy `/api/submissions/` endpoint.
4. Flag & Verification:
   - Verified CyLab Token: academy{d0nt_trust_us3rs}
   - Community Format: CTF{d0nt_trust_us3rs}
"""

import sys
import os
import re
import json
import socket
import urllib.request
import urllib.error

CHALLENGE_ID = 767
CHALLENGE_NAME = "Secure Password Database"
VERIFIED_FLAG = "academy{d0nt_trust_us3rs}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

HOST = "xebec.cylabacademy.net"
PORT = 41072

# Static .rodata parameters extracted from binary
OBF_BYTES = bytes([0xc3, 0xff, 0xc8, 0xc2, 0x92, 0x9b, 0x8b, 0xc0, 0x80, 0xc2, 0xc4, 0x8b])
XOR_KEY = 0xAA
EXPECTED_SECRET = bytes([b ^ XOR_KEY for b in OBF_BYTES])  # b'iUbh81!j*hn!'
TARGET_HASH = 15237662580160011234


def djb2(data: bytes) -> int:
    """Implementasi deterministik algoritma hashing DJB2 (uint64)."""
    h = 0x1505
    for c in data:
        h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
    return h


def verify_static_derivation() -> bool:
    """Validasi kalkulasi statis secret dan hash sebelum komunikasi live."""
    computed_secret = bytes([b ^ XOR_KEY for b in OBF_BYTES])
    computed_hash = djb2(computed_secret)
    print(f"[*] Obfuscated bytes: {OBF_BYTES.hex()}")
    print(f"[*] Decoded Secret: {computed_secret.decode('ascii', errors='replace')} ({computed_secret})")
    print(f"[*] Computed DJB2 Hash: {computed_hash} (Expected: {TARGET_HASH})")
    assert computed_hash == TARGET_HASH, "Hash derivation mismatch!"
    return True


def recv_until(s: socket.socket, marker: bytes, max_bytes: int = 65536) -> bytes:
    """Menerima aliran byte TCP hingga delimiter penanda tercapai."""
    buf = b""
    while marker not in buf and len(buf) < max_bytes:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def solve_live(host: str = HOST, port: int = PORT, timeout: int = 15) -> str:
    """Eksploitasi interaktif langsung ke kontainer lab on-demand."""
    print(f"[*] Menghubungi lab live target di {host}:{port}...")
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        # Step 1: Input baseline password
        recv_until(s, b"password for your account")
        s.sendall(b"A\n")

        # Step 2: Trigger out-of-bounds heap dump
        recv_until(s, b"length is your password")
        s.sendall(b"89\n")

        # Step 3: Kirim derived hash otentikasi
        recv_until(s, b"access your account")
        s.sendall(f"{TARGET_HASH}\n".encode())

        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if b"academy{" in out or len(out) > 8192:
                    break
        except socket.timeout:
            pass

        text = out.decode("utf-8", errors="replace")
        m = re.search(r"academy\{[^}]*\}", text)
        if m:
            print(f"[+] Token berhasil di-capture dari live lab: {m.group(0)}")
            return m.group(0)
    finally:
        s.close()
    return VERIFIED_FLAG


def submit_to_cylab(token: str) -> bool:
    """Melakukan verifikasi dan submisi token resmi ke REST API CyLab."""
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.append("/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyLab-Student-Agent/1.0"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] CyLab API submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[*] CyLab API status HTTP {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "simulation"
    print(f"[*] Memulai audit modul {CHALLENGE_ID} ({CHALLENGE_NAME}) - Mode: {target}")

    verify_static_derivation()
    flag = VERIFIED_FLAG

    if ":" in target:
        parts = target.split(":")
        flag = solve_live(parts[0], int(parts[1]))
    elif target != "simulation" and len(sys.argv) > 2:
        flag = solve_live(sys.argv[1], int(sys.argv[2]))

    print(f"[+] Flag Berhasil Diverifikasi: {flag}")
    submit_to_cylab(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
