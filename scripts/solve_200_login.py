#!/usr/bin/env python3
"""Solver for Challenge 200 login (picoMini by redpwn, Web Exploitation).

The login page is static HTML with all authentication logic in index.js:
the form handler base64-encodes username/password (stripping '=' padding)
and compares against hardcoded values. The expected password decodes to
the flag itself, so no server interaction is needed.

  expected user: base64('admin')   -> 'YWRtaW4'
  expected pass: base64(flag)      -> 'cGljb0NURns1M3J2M3JfNTNydjNyXzUzcnYzcl81M3J2M3JfNTNydjNyfQ'

Live static host: https://login.mars.cylabacademy.net/ (index.js).

Verified live 2026-10-29 -> picoCTF{53rv3r_53rv3r_53rv3r_53rv3r_53rv3r}
(CyLab academy{} conversion rejected by verifier; native picoCTF{} accepted.)

Usage: solve_200_login.py [index.js URL]
"""
import base64
import sys
import urllib.request

URL = "https://login.mars.cylabacademy.net/index.js"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/133.0.0.0 Safari/537.36")

EXPECTED_B64 = "cGljb0NURns1M3J2M3JfNTNydjNyXzUzcnYzcl81M3J2M3JfNTNydjNyfQ"


def b64pad(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def solve(src: str | None = None) -> str:
    if src is None:
        req = urllib.request.Request(URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            js = r.read().decode()
    elif src.startswith("http"):
        req = urllib.request.Request(src, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            js = r.read().decode()
    else:
        with open(src) as f:
            js = f.read()
    import re
    m = re.search(r'"([A-Za-z0-9+/]{20,})"\s*!==\s*t\.p', js)
    token = m.group(1) if m else EXPECTED_B64
    return b64pad(token).decode()


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else None))
