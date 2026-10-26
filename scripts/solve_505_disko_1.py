#!/usr/bin/env python3
"""
Solver for Challenge 505: DISKO 1 (Forensics)
Extracts flag from disk image using regex string matching on decompressed stream.
"""
import urllib.request
import gzip
import re

def solve(url="https://challenge-files.cylabacademy.net/library/ec407404f30c398e6779a1126e6d620b2c86b5f9e14afa720f70614a4e0a21bf/disko-1.dd.gz"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        with gzip.GzipFile(fileobj=resp) as gz:
            while chunk := gz.read(1024 * 1024):
                match = re.search(rb'academy\{[^}]+\}', chunk)
                if match:
                    return match.group(0).decode("utf-8")
    raise ValueError("Flag not found in disk image")

if __name__ == "__main__":
    print("Flag:", solve())
