#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 58: Warmed Up (picoCTF 2019)
Category: General Skills / Radix Conversion & Hexadecimal Representation
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Information System Architecture & Data Encoding Analysis)
CWE: CWE-704 (Incorrect Type Conversion or Cast)

Description:
What is 0x3D (base 16) in decimal (base 10)?
Submit your answer in our flag format: academy{<decimal>}

Methodology:
- Value 0x3D in hexadecimal (base 16) converted to decimal (base 10):
  0x3D = (3 * 16^1) + (13 * 16^0) = 48 + 13 = 61
- Flag format: academy{61}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import sys

EXPECTED_HEX = "0x3D"
EXPECTED_FLAG = "academy{61}"


def solve(hex_str: str = EXPECTED_HEX) -> str:
    dec_val = int(hex_str, 16)
    flag = f"academy{{{dec_val}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    raw_hex = sys.argv[1] if len(sys.argv) > 1 else EXPECTED_HEX
    flag = solve(raw_hex)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
