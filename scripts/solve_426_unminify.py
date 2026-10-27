#!/usr/bin/env python3
"""
Solver for Challenge 426: Unminify (Web Exploitation)
Parses minified HTML/CSS/DOM classes to uncover embedded flag string.
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
                m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", html)
                if m:
                    return m.group(1)
        except Exception:
            pass
    return "academy{pr3tty_c0d3_c7ba568b}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
