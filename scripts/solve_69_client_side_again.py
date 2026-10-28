"""Solver for challenge 69 Client-side-again (picoCTF 2019, Web).

The login portal validates the password purely in obfuscated JavaScript: a
string array rotated 435 times (435 mod 10 = 5 -> left rotation by 5), then
per-segment substring checks. Reconstruct the password from the segment
constraints instead of running the page.

Result: academy{not_this_again_3b977f}

Usage: solve_69_client_side_again.py <base_url>
"""
import re
import sys
import urllib.request

SEGMENTS = {
    (0, 8): 'academy{',
    (3, 6): 'dem',
    (6, 11): 'y{not',
    (7, 9): '{n',
    (8, 16): 'not_this',
    (12, 16): 'this',
    (16, 24): '_again_3',
    (24, 30): 'b977f}',
}


def reconstruct() -> str:
    buf = ['?'] * 30
    for (a, b), seg in SEGMENTS.items():
        for i, ch in enumerate(seg):
            if a + i < len(buf):
                if buf[a + i] != '?' and buf[a + i] != ch:
                    raise ValueError('conflicting constraints')
                buf[a + i] = ch
    pw = ''.join(buf)
    assert '?' not in pw
    for (a, b), seg in SEGMENTS.items():
        assert pw[a:b] == seg, (a, b)
    return pw


def solve(base: str) -> str:
    base = base.rstrip('/')
    page = urllib.request.urlopen(base + '/', timeout=20).read().decode(errors='replace')
    assert 'substring' in page and 'academy{' in page, 'unexpected page'
    return reconstruct()


if __name__ == '__main__':
    print(solve(sys.argv[1] if len(sys.argv) > 1 else 'http://xebec.cylabacademy.net:24757'))
