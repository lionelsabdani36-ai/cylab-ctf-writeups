#!/usr/bin/env python3
"""
Solver for Challenge 527: Log Hunt (General Skills)
Reconstructs fragmented flag from timestamp-ordered server logs.
"""
import urllib.request
import re

def solve(url="https://challenge-files.cylabacademy.net/library/fefc39d7d9da79e3c3f78f0d7f12f520ca703a48a89fa1cac6856a5c2127a4e9/server.log"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        lines = resp.read().decode("utf-8").splitlines()
    
    parts = []
    seen = set()
    for line in lines:
        match = re.search(r'FLAGPART:\s*(\S+)', line)
        if match:
            part = match.group(1)
            if part not in seen:
                seen.add(part)
                parts.append(part)
            if part.endswith('}'):
                break
    return "".join(parts)

if __name__ == "__main__":
    print("Flag:", solve())
