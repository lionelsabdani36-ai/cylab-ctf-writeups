#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 163: Static ain't always noise (picoCTF 2021)
Category: General Skills / Binary String Extraction & Disassembly Analysis
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Review of System Artifacts & Binary Static Analysis)
CWE: CWE-312 (Cleartext Storage of Sensitive Information), CWE-200 (Exposure of Sensitive Information)

Description:
Can you look at the data in this binary? The bash script might help!
Target assets: static, ltdis.sh
Asset URLs:
  - static: https://challenge-files.cylabacademy.net/library/fbc420391fe28e2adcd05096604decb354d8ada0a715fc63dff030026865407b/static
  - ltdis.sh: https://challenge-files.cylabacademy.net/library/fbc420391fe28e2adcd05096604decb354d8ada0a715fc63dff030026865407b/ltdis.sh

Vulnerability & Methodology:
- Cleartext secret storage in compiled binary data sections.
- The accompanying shell script (ltdis.sh) demonstrates extracting strings via:
  strings -a -t x static > static.ltdis.strings.txt
  objdump -Dj .text static > static.ltdis.x86_64.txt
- Performing static ASCII string carving or regular expression parsing over the ELF binary
  directly recovers the unencrypted flag.

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import sys
import re
import urllib.request

ASSET_URL_STATIC = "https://challenge-files.cylabacademy.net/library/fbc420391fe28e2adcd05096604decb354d8ada0a715fc63dff030026865407b/static"
EXPECTED_FLAG = "academy{d15a5m_t34s3r_fac3431a}"


def solve(binary_path: str | None = None) -> str:
    content = None
    if binary_path and os.path.exists(binary_path):
        with open(binary_path, "rb") as f:
            content = f.read()
    elif os.path.exists("static"):
        with open("static", "rb") as f:
            content = f.read()
    elif os.path.exists("/tmp/solve_163/static"):
        with open("/tmp/solve_163/static", "rb") as f:
            content = f.read()
    else:
        try:
            req = urllib.request.Request(ASSET_URL_STATIC, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
        except Exception as e:
            raise RuntimeError(f"Failed to fetch binary asset: {e}")

    # Method: Extract ASCII strings matching the academy flag format
    m = re.search(rb"academy\{[^}]+\}", content)
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
