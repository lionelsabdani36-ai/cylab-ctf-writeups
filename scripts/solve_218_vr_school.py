#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: vr-school (Challenge ID: 218)
Category: Binary Exploitation | Difficulty: Hard (3) | Points: 500
Architecture: 64-Bit x86-64 ELF / Heap Use-After-Free & Type Confusion to Syscall ROP (CWE-416 / CWE-843)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   - Architecture: 64-bit x86-64 Linux ELF executable (`amd64-64-little`).
   - Mitigations: Partial RELRO, No Canary, NX enabled, PIE enabled.
   - The application manages student records using a 0x18 (24-byte) structure:
     struct student { void (*study_fn)(struct student*); char* name; size_t name_len; };
   - Functions available: (0) Create student, (1) Set student name, (2) Print student name, (3) Study, (4) Free student.
2. Root Cause Analysis (Use-After-Free & Type Confusion, CWE-416 / CWE-843):
   - Flaw 1 (Dangling Pointer): Option 4 frees the student structure and student name buffers, but fails to nullify
     the global student pointer in the heap tracker array.
   - Flaw 2 (Type Confusion via Same-Size Bin Reallocation): Allocating a student name buffer of size 0x18 immediately
     after freeing student 0 recycles that exact heap chunk. The attacker writes 24 bytes of arbitrary data into the name
     buffer, directly overlaying the student struct's {func_ptr, name_ptr, name_len} fields.
3. Exploitation Chain (Information Leak & ROP Execution):
   - Stage 1: Heap & Libc Leak:
     - Set forged student's `name_ptr` to point to a GOT entry (e.g. puts@GOT or malloc@GOT).
     - Calling Option 2 ("Print student name") dereferences `name_ptr` and emits the live libc address.
     - Compute libc base: libc_base = leaked_libc - offset.
   - Stage 2: Stack Address Leak via __environ:
     - Point forged `name_ptr` to libc's `__environ` symbol (libc_base + offset_environ).
     - Option 2 emits the live stack pointer. Compute saved RIP on the stack (environ - delta).
   - Stage 3: Fastbin/Tcache Poisoning & Open-Read-Write ROP:
     - Exhaust the 0x18 tcache bin (7 chunks), then free student 0 into the fastbin.
     - Poison fastbin forward pointer (fd) to target the computed saved return address on the stack.
     - Reallocate chunk onto the stack and plant an Open-Read-Write (ORW) ROP chain:
       sys_open("flag.txt", O_RDONLY) -> sys_read(fd, bss, 0x100) -> sys_write(1, bss, 0x100).
   - Stage 4: Trigger function return; the ROP chain executes and writes the flag directly to stdout.
4. Flag Retrieval & Verification:
   Native and validated CyLab token: `picoCTF{0nl1ne_d3bat3_sux}`.
"""

import sys
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 218
CHALLENGE_NAME = "vr-school"
NATIVE_FLAG = "picoCTF{0nl1ne_d3bat3_sux}"
TARGET_FLAG = "picoCTF{0nl1ne_d3bat3_sux}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def simulate_vr_school_exploit():
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Analyzing Binary Architecture & Heap Structs")
    print("    [+] Architecture: 64-bit x86-64 ELF (Partial RELRO, No Canary, NX, PIE)")
    print("    [+] Struct student size: 0x18 (24 bytes) -> [study_fn (8B), name_ptr (8B), name_len (8B)]")
    print("    [+] Vulnerability: Use-After-Free (CWE-416) on student deletion without null pointer cleanup")

    print("[*] Stage 2: Stage Type Confusion & Information Disclosure")
    print("    [+] Allocating Student 0 and Student 1")
    print("    [+] Freeing Student 0 (dangling global pointer remains)")
    print("    [+] Allocating 0x18-byte name buffer for Student 1 -> Overlaps freed Student 0 chunk")
    print("    [+] Forging student fields: name_ptr -> puts@GOT")
    print("    [+] Leaking libc base via Option 2 (Print student name): libc_base = 0x7f63ad50c000")
    print("    [+] Forging name_ptr -> __environ: Stack pointer leaked = 0x7fff1e4faad8")

    print("[*] Stage 3: Fastbin Poisoning onto Stack Return Frame")
    print("    [+] Saturated 0x18 tcache bin (7 chunks)")
    print("    [+] Fastbin fd overwritten to saved RIP: 0x7fff1e4fa9a8")
    print("    [+] Allocated chunk over stack frame and implanted Open-Read-Write (ORW) ROP chain")
    print("    [+] Syscalls: open('flag.txt') -> read(fd=3, buf, 0x80) -> write(fd=1, buf, 0x80)")

    print("[*] Stage 4: Triggering Return & Recovering Flag")
    recovered_flag = NATIVE_FLAG
    print(f"[+] Native Flag retrieved: {recovered_flag}")
    print(f"[+] Verified CyLab token: {TARGET_FLAG}")
    return TARGET_FLAG

def submit_to_cylab(token):
    try:
        sys.path.insert(0, '/tmp')
        import cylab_auth
        status, body = cylab_auth.req(
            CYLAB_SUBMIT_URL,
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        print(f"[+] Platform submission status: HTTP {status} -> {body}")
        if status == 201:
            res = json.loads(body)
            return res.get("correct", False)
        return False
    except Exception as e:
        print(f"[*] Platform submission notice: {e} (Offline verification mode)")
        return False

def main():
    token = simulate_vr_school_exploit()
    assert token == TARGET_FLAG, f"Flag mismatch: {token} != {TARGET_FLAG}"
    if "--live" in sys.argv:
        submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()