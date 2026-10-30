#!/usr/bin/env python3
"""Solver for Challenge 367 ReadMyCert (picoCTF 2023, Cryptography).

Static challenge (no instance): download the CSR file and read the
Subject CN with openssl. The flag sits in plaintext in the CN field.

Usage: solve_367_readmycert.py
Verified: academy{read_mycert_a209fd00} (POST /api/submissions/ -> correct:true)
"""
import re
import subprocess
import urllib.request

CSR_URL = ("https://challenge-files.cylabacademy.net/library/"
           "92fed3a50776fa973c4930638dec4b46f68387dc92043d306d428004dd8da98b/"
           "readmycert.csr")
EXPECTED = "academy{read_mycert_a209fd00}"
FLAG_RE = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def solve(url=CSR_URL):
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0"})
    csr = urllib.request.urlopen(req, timeout=60).read()
    p = subprocess.run(["openssl", "req", "-in", "/dev/stdin",
                        "-text", "-noout"],
                       input=csr, capture_output=True, timeout=60)
    out = p.stdout.decode(errors="replace")
    m = FLAG_RE.search(out)
    if not m:
        raise RuntimeError("flag not found: " + out[:300])
    return m.group(0)


if __name__ == "__main__":
    print(solve())
