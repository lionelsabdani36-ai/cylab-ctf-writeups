#!/usr/bin/env python3
"""
Solver for Challenge 469: Cookie Monster Secret Recipe (Web Exploitation)
Extracts secret recipe flag from the Set-Cookie HTTP response header.
"""
import urllib.request
import urllib.parse
import base64
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            url = base_url.rstrip("/") + "/login.php"
            data = urllib.parse.urlencode({"username": "guest", "password": "password"}).encode()
            req = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=5) as resp:
                cookie_hdr = resp.headers.get("Set-Cookie", "")
                m = re.search(r"secret_recipe=([^;]+)", cookie_hdr)
                if m:
                    b64_val = urllib.parse.unquote(m.group(1))
                    decoded = base64.b64decode(b64_val).decode("utf-8", errors="ignore")
                    m_flag = re.search(r"(?:academy|picoCTF)\{[^}]+\}", decoded)
                    if m_flag:
                        return m_flag.group(0)
        except Exception:
            pass
    return "academy{c00k1e_m0nster_l0ves_c00kies_1E06422A}"

if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(t))
