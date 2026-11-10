#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 255: Bbbbloat (picoCTF 2022)
Category: Reverse Engineering / Binary Deobfuscation & Dead-Code Elimination
Difficulty: Medium | Points: 100
Author: LT 'syreal' Jones
Standard Reference: NIST SP 800-115 § 4.2 (Binary Static Analysis & Obfuscation Deconstruction)
CWE: CWE-200 / CWE-798 (Client-Side Hardcoded Secrets), CWE-514 / CWE-1164 (Dead Code / Arithmetic Bloat)

Description:
Can you get the flag? Reverse engineer this binary:
https://challenge-files.cylabacademy.net/library/e4f53b5263b966ad335fed2c42a9bf41c69b5cbc39c0a30a094e2f267e1a27e0/bbbbloat
The program asks "What's my favorite number?". Upon providing the correct integer,
it decodes and prints the flag.

Vulnerability Analysis & Core Concept:
- Static Analysis of Stripped x86-64 ELF Binary:
  Although stripped of symbols, disassembly of the main entry point reveals:
  1. Arithmetic Bloat Insertion (CWE-1164): Repeated arithmetic sequences
     (mov, add 0x13c29e, sub 0x30a8, shl 1, imul 0x55555556, etc.) modify [rbp-0x3c]
     in an attempt to obfuscate control flow and inflate binary complexity.
  2. Hardcoded Comparison Constant:
     The user input read via __isoc99_scanf("%d", &[rbp-0x40]) is compared via:
       cmp eax, 0x86187 (decimal 549255)
       jne fail_branch
  3. Embedded Obfuscated Stack String (CWE-798):
     Four 64-bit quadwords are loaded onto stack slots [rbp-0x30] .. [rbp-0x18]:
       0x4C4A3E3635323432 -> b"24256>JL"
       0x3062396630664634 -> b"4Ff0f9b0"
       0x34603066635F3D33 -> b"3=_cf0`4"
       0x004E606763326237 -> b"7b2cg`N\x00"
  4. ROT47 Inversion Function:
     Upon passing the comparison, the subroutine at offset 0x1249 iterates over each byte:
     For character c with 0x20 < c and c != 0x7f:
       v = c + 0x2f
       if v > 0x7e: v -= 0x5e
     This corresponds exactly to the classical ROT47 reciprocal permutation across ASCII [33..126].
- Pure Deterministic Emulation:
  Because the binary and its algorithm are fully revealed by disassembly, the flag can be
  extracted deterministically without requiring dynamic execution or native CPU execution.

Recovered Flag: academy{cu7_7h3_bl047_1cf3a481}
Verified: POST /api/submissions/ -> HTTP 201 Created (correct: true)
"""

import json
import os
import struct
import sys
import urllib.request

CHALLENGE_ID = 255
CHALLENGE_NAME = "Bbbbloat"
EXPECTED_FLAG = "academy{cu7_7h3_bl047_1cf3a481}"
FAVORITE_NUMBER = 0x86187  # 549255 in decimal
URL = ("https://challenge-files.cylabacademy.net/library/"
       "e4f53b5263b966ad335fed2c42a9bf41c69b5cbc39c0a30a094e2f267e1a27e0/bbbbloat")

# 4 quadwords extracted directly from binary disassembly at main()
QWORDS = (0x4C4A3E3635323432, 0x3062396630664634, 0x34603066635F3D33, 0x004E606763326237)
BLOB = struct.pack("<4Q", *QWORDS).rstrip(b"\x00")


def rot47_decode(data: bytes) -> str:
    """Applies the reverse-engineered ROT47 transformation from function 0x1249."""
    out = []
    for b in data:
        if b <= 0x20 or b == 0x7F:
            out.append(chr(b))
            continue
        v = b + 0x2F
        if v > 0x7E:
            v -= 0x5E
        out.append(chr(v))
    return "".join(out)


def solve_offline() -> str:
    """Decodes flag using embedded quadwords and pure Python emulation."""
    print(f"[*] Auditing Module {CHALLENGE_ID}: {CHALLENGE_NAME}")
    print(f"[*] Stage 1: Static Parameter Resolution -> Favorite Number: {FAVORITE_NUMBER} (0x{FAVORITE_NUMBER:X})")
    print(f"[*] Stage 2: Unpacking 31-byte stack blob: {BLOB.decode('latin1', errors='replace')}")
    flag = rot47_decode(BLOB)
    print(f"    [+] Decoded Flag: {flag}")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
    return flag


def solve(src: str | None = None) -> str:
    """Extracts flag from binary file or uses embedded stack quadwords."""
    if src and os.path.isfile(src):
        with open(src, "rb") as f:
            content = f.read()
        needle = struct.pack("<Q", QWORDS[0])
        idx = content.find(needle)
        if idx != -1:
            raw_blob = content[idx:idx + 32].rstrip(b"\x00")
            return rot47_decode(raw_blob)
    return solve_offline()


def submit_to_cylab(token: str) -> bool:
    """Submits token to CyLab REST API verification gate."""
    sys.path.insert(0, "/tmp")
    try:
        import cylab_auth
        status, body = cylab_auth.req(
            "https://learn.cylabacademy.org/api/submissions/",
            method="POST",
            data=json.dumps({"challenge": CHALLENGE_ID, "flag": token}).encode("utf-8")
        )
        data = json.loads(body)
        return (status == 201 and data.get("correct") is True)
    except Exception as e:
        print(f"[-] Live submission check failed: {e}")
        return False


if __name__ == "__main__":
    s = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(s)
    print(f"[+] Output Flag: {flag}")
    assert flag == EXPECTED_FLAG
