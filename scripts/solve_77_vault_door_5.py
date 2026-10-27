#!/usr/bin/env python3
"""
Solver for Challenge 77: vault-door-5 (Reverse Engineering)
Inverts Base64 and URL encoding to recover the original vault password.
"""
import base64
import urllib.parse

def solve(expected: str = ("JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm"
                           "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2"
                           "JTM0JTVmJTM5JTM1JTMzJTY1JTM5JTMzJTMwJTMx")) -> str:
    url_encoded = base64.b64decode(expected).decode()
    inner = urllib.parse.unquote(url_encoded)
    return f"academy{{{inner}}}"

if __name__ == "__main__":
    print("Flag:", solve())
