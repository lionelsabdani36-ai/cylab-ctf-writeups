#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 86: 2warm (picoCTF 2019)
Category: General Skills / Radix Conversion & Binary Representation
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Information System Architecture & Data Encoding Analysis)
CWE: CWE-704 (Incorrect Type Conversion or Cast)

Description:
Can you convert the number 42 (base 10) to binary (base 2)?
Submit your answer in our competition's flag format: academy{<binary>}

Methodology:
- Number 42 in decimal (base 10) converted to binary (base 2):
  42 = 32 + 8 + 2 = 2^5 + 2^3 + 2^1 = 0b101010
- Strip '0b' prefix -> '101010'
- Flag format: academy{101010}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import sys

EXPECTED_NUMBER = 42
EXPECTED_FLAG = "academy{101010}"


def solve(number: int = EXPECTED_NUMBER) -> str:
    binary_str = bin(number)[2:]
    flag = f"academy{{{binary_str}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    num = int(sys.argv[1]) if len(sys.argv) > 1 else EXPECTED_NUMBER
    flag = solve(num)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
