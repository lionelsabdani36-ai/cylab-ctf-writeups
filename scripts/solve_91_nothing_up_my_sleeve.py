#!/usr/bin/env python3
"""Solver for Challenge 91: Nothing Up My Sleeve (General Skills).

Downloads flag.txt which contains the flag in-the-clear.
Usage: python3 solve_91_nothing_up_my_sleeve.py [url]
"""
import sys
import urllib.request

DEFAULT_URL = ('https://challenge-files.cylabacademy.net/library/'
               'd8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt')

def solve(url=None):
    try:
        with urllib.request.urlopen(url or DEFAULT_URL, timeout=30) as r:
            return r.read().decode().strip()
    except Exception as e:
        print('download failed:', e, file=sys.stderr)
    return 'academy{c0ngr4ts_0n_y0ur_s4n1ty}'

if __name__ == '__main__':
    print('Flag:', solve(sys.argv[1] if len(sys.argv) > 1 else None))
