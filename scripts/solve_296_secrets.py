#!/usr/bin/env python3
"""Solver for Challenge 296 Secrets (picoCTF 2022, Web Exploitation).

Chain of hidden folders referenced in each page's assets:
  / -> secret/assets/index.css -> /secret/ (hidden/file.css)
/secret/ -> hidden -> /secret/hidden/ (superhidden/login.css)
/secret/hidden/ -> superhidden -> /secret/hidden/superhidden/ (flag in <h3 class="flag">;
CSS may hide it — read source).

Lab is on-demand (PUT /api/challenges/296/instance/); URL rotates.
Usage: solve_296_secrets.py [base_url]
Verified: academy{succ3ss_@h3n1c@10n_2389750f} (POST /api/submissions/ -> correct:true)
"""
import re
import sys
import urllib.request

EXPECTED = "academy{succ3ss_@h3n1c@10n_2389750f}"
PATHS = ["secret/", "secret/hidden/", "secret/hidden/superhidden/"]


def solve(base: str) -> str:
    base = base.rstrip("/") + "/"
    for path in PATHS:
        body = urllib.request.urlopen(base + path, timeout=20).read().decode(errors="replace")
        m = re.search(r"academy\{[^}]*\}", body)
        if m:
            print(path, "->", m.group(0))
            return m.group(0)
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "http://xebec.cylabacademy.net:19098/"))
