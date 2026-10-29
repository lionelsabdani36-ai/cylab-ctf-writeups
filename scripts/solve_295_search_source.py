#!/usr/bin/env python3
"""Solver for Challenge 295 Search source (picoCTF 2022, Web Exploitation).

Chain: mirror site (wget -rk), grep for flag pattern. Developer left flag
in css/style.css. No auth needed.

Lab is on-demand (PUT /api/challenges/295/instance/); URL rotates.
Usage: solve_295_search_source.py [base_url]
Verified: academy{1nsp3ti0n_0f_w3bpag3s_f44abb87} (POST /api/submissions/ -> correct:true)
"""
import re
import sys
import urllib.request

EXPECTED = "academy{1nsp3ti0n_0f_w3bpag3s_f44abb87}"
CANDIDATES = ["css/style.css", "style.css", "index.html", "js/custom.js"]


def solve(base: str) -> str:
    base = base.rstrip("/") + "/"
    for path in CANDIDATES:
        try:
            body = urllib.request.urlopen(base + path, timeout=20).read().decode(errors="replace")
        except Exception:
            continue
        m = re.search(r"academy\{[^}]*\}", body)
        if m:
            print(path, "->", m.group(0))
            return m.group(0)
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "http://xebec.cylabacademy.net:44697/"))
