#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 170: Wave a flag (picoCTF 2021)
Category: General Skills / Linux CLI Parameter Invocation & Binary String Carving
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Command-Line Parameter Enumeration & Artifact Review)
CWE: CWE-200 (Exposure of Sensitive Information)

Description:
Can you invoke help flags for a tool or binary? This program has extraordinarily
helpful information...
Target asset: warm
Asset URL: https://challenge-files.cylabacademy.net/library/66dd9288cd84ecc152a833ed9b86decbf99f8f652f2989fa5bd37801de613ed6/warm

Vulnerability & Methodology:
- CLI argument parsing inspection (`-h` parameter trigger).
- Static byte analysis reveals string literal embedded inside ELF rodata section.
- Executing `./warm -h` or parsing strings extracts:
  academy{b1scu1ts_4nd_gr4vy_57d8c79}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import sys
import re
import subprocess
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/66dd9288cd84ecc152a833ed9b86decbf99f8f652f2989fa5bd37801de613ed6/warm"
EXPECTED_FLAG = "academy{b1scu1ts_4nd_gr4vy_57d8c79}"


def solve(binary_path: str | None = None) -> str:
    content = None
    target_file = None

    if binary_path and os.path.exists(binary_path):
        target_file = binary_path
    elif os.path.exists("warm"):
        target_file = "warm"
    elif os.path.exists("/tmp/solve_170/warm"):
        target_file = "/tmp/solve_170/warm"
    else:
        target_file = "/tmp/warm_170"
        try:
            req = urllib.request.Request(ASSET_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                with open(target_file, "wb") as f:
                    f.write(resp.read())
        except Exception as e:
            raise RuntimeError(f"Failed to fetch binary asset: {e}")

    # Method 1: Execute binary with -h argument if on Linux x86_64
    try:
        os.chmod(target_file, 0o755)
        res = subprocess.run([os.path.abspath(target_file), "-h"], capture_output=True, text=True, timeout=5)
        m = re.search(r'academy\{[^}]+\}', res.stdout + res.stderr)
        if m:
            flag = m.group(0)
            assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
            return flag
    except Exception:
        pass

    # Method 2: Static carving over raw ELF binary bytes
    with open(target_file, "rb") as f:
        raw = f.read()

    m = re.search(rb'academy\{[^}]+\}', raw)
    if m:
        flag = m.group(0).decode("utf-8", errors="ignore")
        assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
        return flag

    raise ValueError("Flag pattern not found in binary")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(path)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
