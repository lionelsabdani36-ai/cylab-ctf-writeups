#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 266: file-run1 (picoCTF 2022)
Category: Reverse Engineering / Linux Binary Execution & Static Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Object Code and Binary Analysis Techniques)
CWE: CWE-312 (Cleartext Storage of Sensitive Information), CWE-798 (Use of Hard-coded Credentials)

Description:
A program has been provided to you, what happens if you try to run it on the command line?
Download the program and run it to get the flag.

Methodology:
- The target asset is an unstripped ELF 64-bit LSB executable binary (size: 16,000 bytes).
- Analysis reveals the binary prints the flag directly upon invocation without requiring CLI arguments.
- Static inspection via string scanning locates the embedded pattern:
  academy{U51N6_Y0Ur_F1r57_F113_4640f37e}
- Dynamic execution with chmod +x ./run confirms standard output:
  The flag is: academy{U51N6_Y0Ur_F1r57_F113_4640f37e}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import subprocess
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/4cb47d716d0004f01f73bbcc894465736c68b3c2d78e32c622e5a63c2bcb885e/run"
EXPECTED_FLAG = "academy{U51N6_Y0Ur_F1r57_F113_4640f37e}"


def solve(file_path: str | None = None) -> str:
    data = b""
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            data = f.read()
    elif os.path.exists("run"):
        with open("run", "rb") as f:
            data = f.read()
    elif os.path.exists("/tmp/run_266/run"):
        with open("/tmp/run_266/run", "rb") as f:
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

    # Step 1: Validate ELF magic bytes
    if not data.startswith(b"\x7fELF"):
        raise ValueError("Invalid ELF binary signature")

    # Step 2: Extract flag statically via regex
    m = re.search(rb"(?:academy|picoCTF)\{[^}]+\}", data)
    if m:
        flag = m.group(0).decode("utf-8", errors="ignore")
    else:
        # Dynamic execution fallback
        tmp_path = "/tmp/run_266_exec"
        with open(tmp_path, "wb") as f:
            f.write(data)
        os.chmod(tmp_path, 0o755)
        proc = subprocess.run([tmp_path], capture_output=True, text=True, timeout=5)
        m2 = re.search(r"(?:academy|picoCTF)\{[^}]+\}", proc.stdout)
        if not m2:
            raise ValueError("Flag not found in execution output")
        flag = m2.group(0)

    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(target)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
