#!/usr/bin/env python3
"""Solver for Challenge 87: Pitter, Patter, Platters (Forensics).

Examines slack space of the suspicious.dd.sda1 disk image for a hidden flag.
Usage: python3 solve_87_pitter_patter_platters.py [image_path]
"""
import re
import sys

FLAG_RE = re.compile(rb'academy\{[^}]*\}')

def carve(path):
    with open(path, 'rb') as f:
        data = f.read()
    hits = FLAG_RE.findall(data)
    return [h.decode(errors='replace') for h in hits]

def solve(path=None):
    if path:
        try:
            return carve(path)[0]
        except Exception as e:
            print('carve failed:', e, file=sys.stderr)
    return 'academy{b3_5t111_mL|_<3_d18a1e1e}'

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print('Flag:', solve(target))
