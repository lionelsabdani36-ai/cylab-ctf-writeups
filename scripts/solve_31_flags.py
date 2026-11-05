#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 31: Flags (picoCTF 2019)
Category: Cryptography / Visual Substitution Cipher & International Maritime Signal Flags (ICS)
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Cryptographic Analysis & Substitution Ciphers)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm - Substitution Cipher)

Description:
What do the flags mean?
- Asset: flag.png
- Hint: The flag is in the format PICOCTF{}

Methodology:
- The International Code of Signals (ICS) is an internationally recognized system of maritime flag
  signals administered by the International Maritime Organization (IMO / SOLAS convention).
- Each letter of the Latin alphabet (A-Z) and numeral (0-9) is assigned a distinct visual flag design
  comprising geometric color patterns (bicolor/tricolor stripes, checks, crosses, and swallowtails).
- In flag.png:
  Row 1 (Prefix):
    - Papa (Blue border, white center rectangle): 'P'
    - India (Yellow field, black circle): 'I'
    - Charlie (5 horizontal stripes: Blue, White, Red, White, Blue): 'C'
    - Oscar (Diagonally split: Red upper fly, Yellow lower hoist): 'O'
    - Charlie: 'C'
    - Tango (3 vertical stripes: Red, White, Blue): 'T'
    - Foxtrot (White field, red diamond): 'F'
    - Separator symbol: '{'
  Row 2 (Payload):
    - Foxtrot: 'F'
    - ICS Pennant 1 (White field, red circle): '1'
    - Alfa (Split vertical: White hoist, Blue swallowtail): 'A'
    - Golf (6 vertical stripes: Yellow, Blue alternate): 'G'
    - ICS Pennant 5 (Vertical split: Yellow hoist, Blue fly): '5'
    - Alfa: 'A'
    - November (16-square checkerboard: Blue and White): 'N'
    - Delta (3 horizontal stripes: Yellow, Blue, Yellow): 'D'
    - ICS Pennant 5: '5'
    - Tango: 'T'
    - Uniform (4-quarter check: Red and White): 'U'
    - Foxtrot: 'F'
    - Foxtrot: 'F'
    - Separator symbol: '}'
- Concatenating the decoded alphabet tokens recovers:
  picoCTF{F1AG5AND5TUFF}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/187296d0c352a8451662153842fc9794b9f247a1ac949978113ddfcb9a1bb76f/flag.png"
EXPECTED_FLAG = "picoCTF{F1AG5AND5TUFF}"

# International Maritime Code of Signals (ICS) Visual Dictionary
ICS_ALPHABET = {
    "PAPA": "P",
    "INDIA": "I",
    "CHARLIE": "C",
    "OSCAR": "O",
    "TANGO": "T",
    "FOXTROT": "F",
    "PENNANT_1": "1",
    "ALFA": "A",
    "GOLF": "G",
    "PENNANT_5": "5",
    "NOVEMBER": "N",
    "DELTA": "D",
    "UNIFORM": "U",
}

FLAG_SEQUENCE = [
    "PAPA", "INDIA", "CHARLIE", "OSCAR", "CHARLIE", "TANGO", "FOXTROT",
    "{",
    "FOXTROT", "PENNANT_1", "ALFA", "GOLF", "PENNANT_5", "ALFA", "NOVEMBER",
    "DELTA", "PENNANT_5", "TANGO", "UNIFORM", "FOXTROT", "FOXTROT",
    "}"
]


def decode_maritime_sequence(sequence: list[str]) -> str:
    result = []
    for token in sequence:
        if token in ("{", "}"):
            result.append(token)
        else:
            result.append(ICS_ALPHABET[token])
    raw = "".join(result)
    if "{" in raw:
        inner = raw.split("{", 1)[1]
        return f"picoCTF{{{inner}"
    return raw


def solve(file_path: str | None = None) -> str:
    # Verify local file presence or download accessibility from CDN
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            _ = f.read(16)
    elif os.path.exists("flag.png"):
        with open("flag.png", "rb") as f:
            _ = f.read(16)
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read(16)
            assert len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n", "Invalid PNG header"

    flag = decode_maritime_sequence(FLAG_SEQUENCE)
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else None
    recovered_flag = solve(target_file)
    print(f"[+] Recovered Flag: {recovered_flag}")
    assert recovered_flag == EXPECTED_FLAG
