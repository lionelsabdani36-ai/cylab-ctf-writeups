#!/usr/bin/env python3
"""
Solver for Challenge 19: So Meta (Forensics)
Extracts embedded metadata and flag string from pico_img.png.
"""
import urllib.request
import re

def solve(url: str = "https://challenge-files.cylabacademy.net/library/7d12ed78e80c80afccae7ae860ed2277f044812e86c7267efbf7e0200fc9fd1e/pico_img.png") -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    data = urllib.request.urlopen(req).read()
    m = re.findall(rb"(academy\{[a-zA-Z0-9_]+\}|picoCTF\{[a-zA-Z0-9_]+\})", data)
    if m:
        return m[0].decode()
    return "Flag not found"

if __name__ == "__main__":
    print("Flag:", solve())
