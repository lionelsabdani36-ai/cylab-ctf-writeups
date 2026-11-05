#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 22: Lets Warm Up (picoCTF 2019)
Category: General Skills / ASCII Character Encoding & Byte Representation
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115, RFC 20 (ASCII format for Network Interchange)
CWE: CWE-704 (Incorrect Type Conversion or Cast)

Description:
If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII?
Submit your answer in our flag format: academy{<character>}

Methodology:
- Byte value 0x70 in hexadecimal (base 16) converted to ASCII character:
  0x70 = 7 * 16 = 112 (decimal)
  ASCII code 112 -> 'p'
- Flag format: academy{p}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import sys

EXPECTED_HEX = "0x70"
EXPECTED_FLAG = "academy{p}"


def solve(hex_str: str = EXPECTED_HEX) -> str:
    byte_val = int(hex_str, 16)
    ascii_char = chr(byte_val)
    flag = f"academy{{{ascii_char}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    raw_hex = sys.argv[1] if len(sys.argv) > 1 else EXPECTED_HEX
    flag = solve(raw_hex)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
