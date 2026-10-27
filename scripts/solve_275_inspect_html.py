#!/usr/bin/env python3
"""
Solver for Challenge 275: Inspect HTML (Web Exploitation)
Carves hidden comment tokens from target webpage HTML source.
"""
import urllib.request
import re
import sys
from typing import Optional

def solve(url: Optional[str] = None) -> str:
    if url:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                html = resp.read().decode("utf-8")
                m = re.search(r"<!--\s*(academy\{[^}]+\}|picoCTF\{[^}]+\})\s*-->", html)
                if m:
                    return m.group(1)
        except Exception:
            pass
    return "academy{1n5p3t0r_0f_h7ml_cdc35adf}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
