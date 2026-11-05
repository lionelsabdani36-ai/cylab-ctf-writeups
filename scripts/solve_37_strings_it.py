#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 37: strings it (picoCTF 2019)
Category: General Skills / Binary String Extraction & Static Analysis
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Section 5.3: Object Code & Static Binary Analysis Techniques)
CWE: CWE-312 (Cleartext Storage of Sensitive Information)

Description:
Can you find the flag in file without running it?

Methodology:
- The target asset is an unstripped ELF 64-bit LSB executable binary (size: ~783 KB).
- Executing unknown binaries in an untrusted environment violates defensive principles.
- Utilizing POSIX strings extraction (scanning for contiguous printable ASCII sequences >= 4 chars)
  combined with regular expression matching: (?:academy|picoCTF)\\{[^}]+\\}
- Recovers the hardcoded plaintext flag without executing the binary.
- Recovered flag: academy{5tRIng5_1T_b1e21039}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/dede17d717e026b75f6b9e7fb2c1601b46093ced6f209b8f6b27ffd883a9ae2f/strings"
EXPECTED_FLAG = "academy{5tRIng5_1T_b1e21039}"


def solve(file_path: str | None = None) -> str:
    data = b""
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            data = f.read()
    elif os.path.exists("strings"):
        with open("strings", "rb") as f:
            data = f.read()
    elif os.path.exists("/tmp/strings_37"):
        with open("/tmp/strings_37", "rb") as f:
            data = f.read()
    else:
        req = urllib.request.Request(
            ASSET_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://learn.cylabacademy.org/challenges",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()

    m = re.search(rb"(?:academy|picoCTF)\{[^}]+\}", data)
    if not m:
        raise ValueError("Flag pattern not found in binary strings")

    flag = m.group(0).decode("utf-8", errors="ignore")
    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
