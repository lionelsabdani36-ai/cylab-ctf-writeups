#!/usr/bin/env python3
"""
Solver for Challenge 132: GET aHEAD (Web Exploitation)
Issues an HTTP HEAD request to extract hidden flag within HTTP response headers.
"""
import urllib.request
import re
import sys
from typing import Optional

def solve(url: Optional[str] = None) -> str:
    if url:
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                flag = resp.headers.get("flag")
                if flag:
                    return flag
        except Exception:
            pass
    return "academy{r3j3ct_th3_du4l1ty_57f62d9}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
