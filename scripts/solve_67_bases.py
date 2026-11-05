#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 67: Bases (picoCTF 2019)
Category: General Skills / Base64 Encoding & Radix Representation
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 / RFC 4648 (The Base16, Base32, and Base64 Data Encodings)
CWE: CWE-312 (Cleartext Storage of Sensitive Information) / CWE-327

Description:
What does this `bDNhcm5fdGgzX3IwcDM1` mean? I think it has something to do with bases.
Submit your answer in our flag format: academy{<decoded>}

Methodology:
- Encoded string: 'bDNhcm5fdGgzX3IwcDM1'
- Character set consists of [A-Za-z0-9] conforming to RFC 4648 Base64 alphabet.
- Base64 maps 6-bit binary sequences to printable ASCII characters:
  4 characters represent 3 bytes of raw binary data.
  'bDNh' -> 'l3a', 'cm5f' -> 'rn_', 'dGgz' -> 'th3', 'X3Iw' -> '_r0', 'cDM1' -> 'p35'
- Decoded plaintext: 'l3arn_th3_r0p35'
- Flag format: academy{l3arn_th3_r0p35}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import base64
import sys

TARGET_ENCODED = "bDNhcm5fdGgzX3IwcDM1"
EXPECTED_FLAG = "academy{l3arn_th3_r0p35}"


def solve(encoded_str: str = TARGET_ENCODED) -> str:
    # Ensure correct padding if needed
    padded = encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4)
    decoded_bytes = base64.b64decode(padded)
    decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
    flag = f"academy{{{decoded_str}}}"
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else TARGET_ENCODED
    flag = solve(raw_input)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
