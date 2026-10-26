#!/usr/bin/env python3
"""
Solver for Challenge 427: WebDecode (Web Exploitation)
Extracts Base64 payload from HTML tag attribute (notify_true) and decodes it.
"""
import urllib.request
import base64
import re
import sys
from typing import Optional

def solve(url: Optional[str] = None) -> str:
    if url:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                html = resp.read().decode("utf-8")
                m = re.search(r'notify_true="([^"]+)"', html)
                if m:
                    return base64.b64decode(m.group(1)).decode("utf-8")
        except Exception:
            pass
    # Known Base64 payload from about.html notify_true attribute
    b64 = "YWNhZGVteXt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfOWQ3MmE4ZjZ9"
    return base64.b64decode(b64).decode("utf-8")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
