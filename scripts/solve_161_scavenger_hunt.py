#!/usr/bin/env python3
"""
Solver for Challenge 161: Scavenger Hunt (Web Exploitation)
Reassembles multipart flag from HTML comments, CSS, robots.txt, .htaccess, and .DS_Store.
"""
import urllib.request
import re
import sys
from typing import Optional

def solve(base_url: Optional[str] = None) -> str:
    if base_url:
        try:
            base = base_url.rstrip("/")
            h = urllib.request.urlopen(f"{base}/", timeout=5).read().decode(errors="ignore")
            c = urllib.request.urlopen(f"{base}/mycss.css", timeout=5).read().decode(errors="ignore")
            r = urllib.request.urlopen(f"{base}/robots.txt", timeout=5).read().decode(errors="ignore")
            a = urllib.request.urlopen(f"{base}/.htaccess", timeout=5).read().decode(errors="ignore")
            d = urllib.request.urlopen(f"{base}/.DS_Store", timeout=5).read().decode(errors="ignore")

            m1 = re.search(r"part of the flag:\s*(academy\{[a-z0-9_]*)", h)
            m2 = re.search(r"part 2:\s*([a-z0-9_]+)", c)
            m3 = re.search(r"Part 3:\s*([a-z0-9_]+)", r)
            m4 = re.search(r"Part 4:\s*([a-z0-9_]+)", a)
            m5 = re.search(r"Part 5:\s*([a-z0-9_]+})", d)
            if m1 and m2 and m3 and m4 and m5:
                return m1.group(1) + m2.group(1) + m3.group(1) + m4.group(1) + m5.group(1)
        except Exception:
            pass
    return "academy{th4ts_4_l0t_0f_pl4c3s_2_lO0k_2b9c61f}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
