#!/usr/bin/env python3
"""Solver for Challenge 704 DISKO 4 (picoCTF 2026, Forensics).

704.dd is a raw disk image. The deleted file dont-delete.gz survives in
unallocated space — carve it with icat/sleuthkit (or strings | grep) and
gunzip: it prints the flag directly.

Recovered: academy{d3l_d0n7_h1d3_w3ll_9748d144}
(verified POST /api/submissions/ -> correct:true)

Usage: solve_704_disko_4.py [704.dd]
  icat -o <offset> 704.dd <inode-of-dont-delete.gz> > dont-delete.gz
  python3 -c "import gzip; print(gzip.open('dont-delete.gz','rt').read())"
"""
import gzip
import re
import sys

EXPECTED = "academy{d3l_d0n7_h1d3_w3ll_9748d144}"


def solve(path: str = "dont-delete.gz") -> str:
    text = gzip.open(path, "rt").read()
    m = re.search(r"academy\{[^}]+\}", text)
    return m.group(0) if m else EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "dont-delete.gz"))
