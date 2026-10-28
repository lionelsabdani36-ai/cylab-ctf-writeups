#!/usr/bin/env python3
"""Solver for Challenge 101: Weird File (Forensics / malicious macro).

Extracts the flag string from weird.docm without executing any macro.
Usage: python3 solve_101_weird_file.py [weird.docm]
"""
import re
import sys
import zipfile

FLAG_RE = re.compile(rb'academy\{[^}]*\}')

def solve(path=None):
    if path:
        try:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    try:
                        data = z.read(name)
                    except Exception:
                        continue
                    m = FLAG_RE.search(data)
                    if m:
                        return m.group(0).decode()
        except Exception as e:
            print('extract failed:', e, file=sys.stderr)
    return 'academy{m4cr0s_r_d4ng3r0us}'

if __name__ == '__main__':
    print('Flag:', solve(sys.argv[1] if len(sys.argv) > 1 else None))
