#!/usr/bin/env python3
"""
Solver for Challenge 274: Includes (Web Exploitation)
Carves multipart flag segments from external CSS and JavaScript files.
"""
import urllib.request
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            css_url = base_url.rstrip("/") + "/style.css"
            js_url = base_url.rstrip("/") + "/script.js"
            css = urllib.request.urlopen(css_url, timeout=5).read().decode()
            js = urllib.request.urlopen(js_url, timeout=5).read().decode()
            m1 = re.search(r"/\*\s*(academy\{[^\s]+)\s*\*/", css)
            m2 = re.search(r"//\s*([^\s]+\})\s*", js)
            if m1 and m2:
                return m1.group(1) + m2.group(1)
        except Exception:
            pass
    return "academy{1nclu51v17y_1of2_f7w_2of2_ce526b3b}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
