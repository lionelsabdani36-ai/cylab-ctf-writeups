#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 176: Tab, Tab, Attack (picoCTF 2021)
Category: General Skills / Linux Shell Autocompletion & Deep Directory Carving
Difficulty: Easy (diff=1)
Standard Reference: NIST SP 800-115 (Review of System Configuration & Directory Traversal)
CWE: CWE-200 (Exposure of Sensitive Information)

Description:
Using tabcomplete in the Terminal will add years to your life, esp. when dealing
with long rambling directory structures and filenames.
Target asset: Addadshashanammu.zip
Asset URL: https://challenge-files.cylabacademy.net/library/298b799316c13103156a84f949a6cb6e02efd5cdb0ee09700231527df92ed468/Addadshashanammu.zip

Vulnerability & Methodology:
- Deep nested directory traversal under Unix-like filesystems.
- The archive unpacks 7 layers of directories leading to an ELF binary and C source.
- Strings extraction or execution of `fang-of-haynekhtnamet` reveals:
  academy{l3v3l_up!_t4k3_4_r35t!_9d928112}

Verified: POST /api/submissions/ -> correct: true (HTTP 201)
"""

import os
import sys
import zipfile
import re
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/298b799316c13103156a84f949a6cb6e02efd5cdb0ee09700231527df92ed468/Addadshashanammu.zip"
EXPECTED_FLAG = "academy{l3v3l_up!_t4k3_4_r35t!_9d928112}"


def solve(zip_path: str | None = None) -> str:
    # 1. Obtain zip bytes or file path
    data = None
    if zip_path and os.path.exists(zip_path):
        with open(zip_path, "rb") as f:
            data = f.read()
    elif os.path.exists("Addadshashanammu.zip"):
        with open("Addadshashanammu.zip", "rb") as f:
            data = f.read()
    elif os.path.exists("/tmp/solve_176/Addadshashanammu.zip"):
        with open("/tmp/solve_176/Addadshashanammu.zip", "rb") as f:
            data = f.read()
    else:
        try:
            req = urllib.request.Request(ASSET_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
        except Exception as e:
            raise RuntimeError(f"Failed to fetch zip asset: {e}")

    # 2. Carve zip entries in memory
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for fname in z.namelist():
            if fname.endswith(".c") or "fang" in fname:
                content = z.read(fname)
                m = re.search(rb'academy\{[^}]+\}', content)
                if m:
                    flag = m.group(0).decode("utf-8")
                    assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} != {EXPECTED_FLAG}"
                    return flag

    # 3. Direct binary search fallback
    m = re.search(rb'academy\{l3v3l_up![^}]+\}', data)
    if m:
        return m.group(0).decode("utf-8")

    raise ValueError("Flag pattern not found in archive")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(path)
    print(f"[+] Recovered Flag: {flag}")
    assert flag == EXPECTED_FLAG
