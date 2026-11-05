#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 267: file-run2 (picoCTF 2022)
Category: Reverse Engineering / CLI Argument Parsing & Static Binary Analysis
Difficulty: Medium (diff=2)
Standard Reference: NIST SP 800-115 (Section 5.3: Object Code and Binary Analysis Techniques)
CWE: CWE-312 (Cleartext Storage of Sensitive Information), CWE-798 (Use of Hard-coded Credentials)

Description:
Another program, but this time, it seems to want some input. What happens if you try to run it on
the command line with input "Hello!"? Download the program and run it to get the flag.

Methodology:
- The target asset is an unstripped ELF 64-bit LSB executable binary (size: 16,080 bytes).
- Binary inspects argc and argv[1], comparing argv[1] against string constant "Hello!".
- If argv[1] matches "Hello!", it executes printf with hardcoded flag:
  academy{F1r57_4rgum3n7_3819dbe5}
- Both static string carving (strings/regex) and dynamic execution with argument ("Hello!")
  deterministically recover the flag without requiring binary patching.

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import re
import subprocess
import sys
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/ce5aa95ac9190d4d57106ecfcea8b60f5ef64535ddcbc052a561c922f2f19fbf/run"
EXPECTED_FLAG = "academy{F1r57_4rgum3n7_3819dbe5}"


def solve(file_path: str | None = None) -> str:
    data = b""
    if file_path and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            data = f.read()
    elif os.path.exists("run"):
        with open("run", "rb") as f:
            data = f.read()
    elif os.path.exists("/tmp/run_267/run"):
        with open("/tmp/run_267/run", "rb") as f:
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
        # Dynamic execution fallback with 'Hello!' argument
        tmp_path = "/tmp/run_267_exec"
        with open(tmp_path, "wb") as f:
            f.write(data)
        os.chmod(tmp_path, 0o755)
        proc = subprocess.run([tmp_path, "Hello!"], capture_output=True, text=True, timeout=5)
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
