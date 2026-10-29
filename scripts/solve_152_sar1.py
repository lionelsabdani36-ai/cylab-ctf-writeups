#!/usr/bin/env python3
"""Solver for Challenge 152 Some Assembly Required 1 (picoCTF 2021, Web).

Page loads obfuscated JS + WASM module exposing copy_char/check_flag.
Unlike SAR2, the flag sits PLAINTEXT in the wasm data section -- plain
strings extraction suffices (no XOR layer in this build).

Usage: solve_152_sar1.py [wasm_url_or_path]
Verified: academy{8c87cb4dcc87959c351f832e6a165296}
(POST /api/submissions/ -> correct:true)
"""
import re
import sys
import urllib.request

WASM_URL = "http://chatelaine.cylabacademy.net:43804/JIFxzHyW8W"
EXPECTED = "academy{8c87cb4dcc87959c351f832e6a165296}"
FLAG_RE = re.compile(rb"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def solve(src: str = WASM_URL) -> str:
    if src.startswith("http"):
        req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
    else:
        with open(src, "rb") as f:
            data = f.read()
    print(f"[*] wasm {len(data)} bytes")
    m = FLAG_RE.search(data)
    if not m:
        raise ValueError("flag not found in wasm")
    flag = m.group(0).decode()
    print(f"FLAG: {flag}")
    assert flag == EXPECTED, flag
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else WASM_URL))
