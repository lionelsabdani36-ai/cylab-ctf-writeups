#!/usr/bin/env python3
"""
Solver for Challenge 530: Riddle Registry (Forensics)
Extracts Base64-encoded flag from PDF metadata Author field.
"""
import urllib.request
import re
import base64

def solve(url="https://challenge-files.cylabacademy.net/library/ceb9652e54e6e40458e46a4c7bb96b66980ccd362a7945217cba574db7b7ea0b/confidential.pdf"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        content = resp.read()
    
    # Search for /Author (b64)
    match = re.search(rb'/Author\s*\(([^)]+)\)', content)
    if not match:
        raise ValueError("Author metadata not found")
    
    raw = match.group(1).decode("latin1")
    # Clean octal escapes e.g. \075 -> '='
    cleaned = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), raw)
    flag = base64.b64decode(cleaned).decode("utf-8")
    return flag

if __name__ == "__main__":
    print("Flag:", solve())
