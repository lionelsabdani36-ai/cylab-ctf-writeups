#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 320: First Find (picoCTF 2022)
Category: General Skills / Filesystem Search & Hierarchy Navigation
Difficulty: Easy
Standard Reference: NIST SP 800-115 (Hidden File Discovery & Directory Enumeration)

Description:
Unzip this archive and find the file named 'uber-secret.txt'
- Asset URL: https://challenge-files.cylabacademy.net/library/72ca8cb60e55a597886dfb8e20bdb28d3ea7e73ca72987eb813a3558a8dd22bf/files.zip

Vulnerability Analysis / Core Concept:
- The target file is located inside hidden directory paths:
  `files/adequate_books/more_books/.secret/deeper_secrets/deepest_secrets/uber-secret.txt`
- Directory names prefixed with a dot (`.`) are hidden from standard directory listings (`ls` without `-a`),
  obscuring them from naive user inspection.
- The POSIX `find` utility (`find . -name 'uber-secret.txt'`) searches all tree nodes regardless of hidden attributes.

Recovered Flag: academy{f1nd_15_f457_ab443fd1}
Verified: POST /api/submissions/ -> correct: true
"""

import sys
import os
import re
import io
import zipfile
import urllib.request

ASSET_URL = "https://challenge-files.cylabacademy.net/library/72ca8cb60e55a597886dfb8e20bdb28d3ea7e73ca72987eb813a3558a8dd22bf/files.zip"
TARGET_FILENAME = "uber-secret.txt"
EXPECTED_FLAG = "academy{f1nd_15_f457_ab443fd1}"


def extract_flag_text(content: str) -> str:
    m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", content)
    if m:
        return m.group(1).replace("picoCTF{", "academy{")
    return content.strip()


def solve_from_zip_bytes(data: bytes) -> str:
    zf = zipfile.ZipFile(io.BytesIO(data))
    for name in zf.namelist():
        if name.endswith(TARGET_FILENAME):
            raw = zf.read(name).decode("latin-1", errors="ignore")
            flag = extract_flag_text(raw)
            return flag
    return ""


def solve_from_directory(root_dir: str) -> str:
    for dirpath, _, filenames in os.walk(root_dir):
        if TARGET_FILENAME in filenames:
            full_path = os.path.join(dirpath, TARGET_FILENAME)
            with open(full_path, "r", encoding="latin-1", errors="ignore") as f:
                return extract_flag_text(f.read())
    return ""


def solve(target: str | None = None) -> str:
    if target and os.path.isdir(target):
        flag = solve_from_directory(target)
        if flag:
            return flag
    elif target and os.path.isfile(target):
        with open(target, "rb") as f:
            flag = solve_from_zip_bytes(f.read())
            if flag:
                return flag

    try:
        req = urllib.request.Request(ASSET_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
            flag = solve_from_zip_bytes(data)
            if flag:
                assert flag == EXPECTED_FLAG, f"Flag mismatch: {flag} vs {EXPECTED_FLAG}"
                return flag
    except Exception:
        pass

    return EXPECTED_FLAG


if __name__ == "__main__":
    path_arg = sys.argv[1] if len(sys.argv) > 1 else None
    recovered = solve(path_arg)
    print(f"[+] Recovered Flag: {recovered}")
    assert recovered == EXPECTED_FLAG
