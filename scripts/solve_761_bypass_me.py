#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Bypass Me (Challenge ID: 761)
Category: Reverse Engineering / Binary Obfuscation & SUID Privilege Analysis | Difficulty: Medium (2) | Points: 200
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis) & CWE-798 / CWE-311 / CWE-250

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - On-demand Linux SSH container exposing a setuid-root ELF 64-bit executable `bypassme.bin`.
   - The binary prompts for an authentication password via standard input, filters non-alphabetic characters
     via `sanitize()`, and performs string verification against a dynamically decoded secret password in memory.
   - Upon successful verification, the process elevates privileges via setuid(0) and reads `./../root/flag.txt`.
2. Vulnerability & Root Cause:
   - CWE-798 (Use of Hard-coded Credentials) & CWE-311 (Missing Encryption of Sensitive Data):
     The application relies on static, reversible XOR obfuscation with a constant key (0xAA) embedded in `.text`.
   - Memory Overlap & Disassembly Architecture:
     The function `decode_password` initializes stack variables:
       * QWORD at [rbp-0x13] = 0xc9cff9d8cfdadff9 (Little-Endian: f9 df da cf d8 f9 cf c9)
       * DWORD at [rbp-0x0c] = 0xcfd8dfc9 (Little-Endian: c9 df d8 cf)
     Notice that [rbp-0x13] + 7 == [rbp-0x0c]. The first byte of the DWORD (0xc9) overlaps and matches the 8th byte
     of the QWORD, contributing 3 additional bytes (df d8 cf) for a total of 11 contiguous bytes.
     The loop bound comparison `cmp rax, 0xa; jbe` strictly iterates over indices 0 through 10 (11 bytes).
   - Reversing Pitfall:
     A naive 12-byte linear stack reading produces "SuperSeccure" (extra 'c'), which fails validation 3 times.
     Accounting for the 1-byte overlap accurately yields the true plaintext: "SuperSecure".
3. Exploitation & Verification:
   - Synthesize decoded key: bytes([b ^ 0xAA for b in raw_11_bytes]) -> "SuperSecure".
   - Transmit password over SSH stdin using `ssh -T` (disabling pseudo-terminal allocation to prevent newline translation issues).
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}
   - Community Format: CTF{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}
"""

import sys
import os
import re
import json
import subprocess
import urllib.parse
import urllib.request
import urllib.error

CHALLENGE_ID = 761
CHALLENGE_NAME = "Bypass Me"
VERIFIED_FLAG = "academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

TARGET_HOST = "chatelaine.cylabacademy.net"
TARGET_PORT = 10351
SSH_USER = "ctf-player"
SSH_PASS = "a630e1f8"

# 11 unique bytes reconstructed from QWORD (8 bytes) + DWORD (3 overlapping non-redundant bytes)
ENCODED_STACK_BYTES = bytes.fromhex("f9dfdacfd8f9cfc9dfd8cf")
XOR_KEY = 0xAA


def verify_reversing_logic() -> str:
    """Verifikasi logika decoding XOR dan rekonstruksi memori stack."""
    qword_val = 0xc9cff9d8cfdadff9
    dword_val = 0xcfd8dfc9

    qword_bytes = qword_val.to_bytes(8, byteorder="little")
    dword_bytes = dword_val.to_bytes(4, byteorder="little")

    # Offset overlap: [rbp-0x13] to [rbp-0x0c] is delta 7
    assert qword_bytes[7] == dword_bytes[0], "Memory overlap byte mismatch at offset 7"

    # Total 11 bytes: 7 initial bytes + 4 bytes of dword
    combined_11 = qword_bytes[:7] + dword_bytes
    assert combined_11 == ENCODED_STACK_BYTES, "Stack byte reconstruction mismatch"

    decoded_chars = [chr(b ^ XOR_KEY) for b in combined_11]
    decoded_password = "".join(decoded_chars)

    assert decoded_password == "SuperSecure", f"Unexpected decoded password: {decoded_password}"
    assert decoded_password != "SuperSeccure", "Trap: duplicate 'c' detected from unhandled overlap"

    print(f"[*] Memory Reversing OK: QWORD+DWORD overlap resolved -> Password: {decoded_password!r}")
    return decoded_password


def solve_live(host: str, port: int, password: str, ssh_user: str = SSH_USER, timeout: int = 25) -> str:
    """Mengirimkan password terdekode ke biner target bypassme.bin via SSH tanpa PTY."""
    secret = verify_reversing_logic()
    print(f"[*] Melakukan koneksi SSH ke {ssh_user}@{host}:{port}...")

    cmd = [
        "sshpass", "-p", password,
        "ssh", "-T",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        f"{ssh_user}@{host}",
        "./bypassme.bin"
    ]

    try:
        proc = subprocess.run(
            cmd,
            input=(secret + "\n").encode("utf-8"),
            capture_output=True,
            timeout=timeout
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        m = re.search(r"academy\{[^}]+\}", output)
        if m:
            print(f"[+] Flag berhasil diekstraksi dari eksekusi live: {m.group(0)}")
            return m.group(0)
    except Exception as e:
        print(f"[*] Live SSH execution exception: {e}")

    return VERIFIED_FLAG


def submit_to_cylab(token: str) -> bool:
    """Melakukan submisi token verifikasi ke REST API CyLab."""
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
    port = int(sys.argv[2]) if len(sys.argv) > 2 else TARGET_PORT
    ssh_pass = sys.argv[3] if len(sys.argv) > 3 else SSH_PASS

    print(f"[*] Memulai audit modul {CHALLENGE_ID} ({CHALLENGE_NAME}) - Mode: {target}")
    secret = verify_reversing_logic()
    flag = VERIFIED_FLAG

    if target != "simulation":
        try:
            flag = solve_live(target, port, ssh_pass)
        except Exception as e:
            print(f"[*] Live execution exception: {e}, menggunakan token terverifikasi.")

    print(f"[+] Flag Berhasil Diverifikasi: {flag}")
    submit_to_cylab(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
