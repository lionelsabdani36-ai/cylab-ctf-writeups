#!/usr/bin/env python3
"""Solver for Challenge 131 Some Assembly Required 2 (picoCTF 2021, Web).

Page loads obfuscated JS + WASM module. copy_char XORs each input char with
8 before comparing (strcmp vs encoded data segment). The data segment holds
the XOR-encoded flagняем -- decode offline: bytes ^ 8.

Usage: solve_131_sar2.py [wasm_url]
Verified: academy{217f0babdae45710109bb2e6ac1b134a}
(POST /api/submissions/ -> correct:true)
"""
import re
import sys
import urllib.request

WASM_URL = "http://chatelaine.cylabacademy.net:34767/aD8SvhyVkb"
EXPECTED = "academy{217f0babdae45710109bb2e6ac1b134a}"
FLAG_RE = re.compile(rb"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def extract_strings(data: bytes):
    return re.findall(rb"[ -~]{8,}", data)


def solve(src: str = WASM_URL) -> str:
    if src.startswith("http"):
        req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
    else:
        with open(src, "rb") as f:
            data = f.read()
    print(f"[*] wasm {len(data)} bytes")
    for s in extract_strings(data):
        dec = bytes(b ^ 8 for b in s)
        m = FLAG_RE.search(dec)
        if m:
            flag = m.group(0).decode()
            print(f"FLAG: {flag}")
            assert flag == EXPECTED, flag
            return flag
    raise ValueError("flag not found in wasm strings")


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else WASM_URL))
