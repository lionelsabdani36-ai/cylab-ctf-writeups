#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 147: Obedient Cat (picoCTF 2021)
Category: General Skills / Standard I/O Stream & File Concatenation
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Review of System Artifacts & File System Access)
CWE: CWE-312 (Cleartext Storage of Sensitive Information), CWE-732 (Incorrect Permission Assignment)

Description:
This file has a flag in plain sight (aka "in-the-clear").
Target asset: flag
Asset URL: https://challenge-files.cylabacademy.net/library/11b9e730524b026e2bce9e561dad9e8f1905b575e3fc6a1477eb1698b59e6585/flag

Vulnerability & Methodology:
- Cleartext file storage without access control or cryptographic protection.
- Reading standard stream output via POSIX file utility `cat flag` or direct file reading.
- Recovers: academy{s4n1ty_v3r1f13d_61ddac22}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import sys
import re
import urllib.request

ASSET_URL_FLAG = "https://challenge-files.cylabacademy.net/library/11b9e730524b026e2bce9e561dad9e8f1905b575e3fc6a1477eb1698b59e6585/flag"
EXPECTED_FLAG = "academy{s4n1ty_v3r1f13d_61ddac22}"


def solve(file_path: str | None = None) -> str:
    content = None
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
    elif os.path.exists("flag"):
        with open("flag", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
    elif os.path.exists("/tmp/solve_147/flag"):
        with open("/tmp/solve_147/flag", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
    else:
        try:
            req = urllib.request.Request(ASSET_URL_FLAG, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="ignore").strip()
        except Exception as e:
            raise RuntimeError(f"Failed to fetch flag asset: {e}")

    m = re.search(r"academy\{[^}]+\}", content)
    if m:
        flag = m.group(0)
        assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
        return flag

    raise ValueError("Flag pattern not found in content")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(path)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
