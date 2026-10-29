#!/usr/bin/env python3
"""Solver for Challenge 314 unpackme.py (picoCTF 2022, Reverse Engineering).

The script ships a Fernet token (`payload`) plus the key in source:
key_str = 'correctstaplecorrectstaplecorrec' (32 chars) -> base64 -> Fernet key.
Decrypting reveals an inner script that prints the flag when given password
'batteryhorse'. Static decryption is enough; no need to run the payload.

Usage:
  solve_314_unpackme_py.py [unpackme.flag.py path]
  solve_314_unpackme_py.py --fetch  # download the file from the CDN first

Verified: academy{175_chr157m45_4d521283} (POST /api/submissions/ -> correct:true)
"""
import base64
import re
import sys
import urllib.request

EXPECTED = "academy{175_chr157m45_4d521283}"

URL = ("https://challenge-files.cylabacademy.net/library/"
       "d78f54f4620ec8d4a6f17fa02080e00306f51d33831dd2ea2d1a1366905d3c47/"
       "unpackme.flag.py")


def fetch(path: str = "unpackme.flag.py") -> str:
    req = urllib.request.Request(URL, headers={
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://learn.cylabacademy.org/challenges"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    assert len(data) > 100, "CDN download too short (%d bytes)" % len(data)
    open(path, "wb").write(data)
    print("downloaded %d bytes -> %s" % (len(data), path))
    return path


def solve(path: str = "unpackme.flag.py") -> str:
    from cryptography.fernet import Fernet
    from cryptography.fernet import InvalidToken
    src = open(path, "rb").read()
    m = re.search(rb"b'([A-Za-z0-9_\-=]+)'", src)
    assert m, "Fernet token not found in %s" % path
    blob = m.group(1)
    key_b64 = base64.b64encode(b"correctstaplecorrectstaplecorrec")
    try:
        plain = Fernet(key_b64).decrypt(blob).decode()
    except InvalidToken:
        raise SystemExit(
            "InvalidToken: %s looks like the unauthenticated CDN "
            "placeholder (truncated token). Re-download with --fetch "
            "and a valid CYLAB_COOKIE." % path)
    m2 = re.search(r"academy\{[^}]*\}", plain)
    assert m2, "no flag in decrypted payload: %r" % plain[:200]
    flag = m2.group(0)
    print("password: batteryhorse")
    print("flag:", flag)
    assert flag == EXPECTED, flag
    return EXPECTED


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "unpackme.flag.py"
    print(solve(fetch() if arg == "--fetch" else arg))
