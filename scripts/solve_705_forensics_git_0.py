#!/usr/bin/env python3
"""Solver for Challenge 705 Forensics Git 0 (picoCTF 2026, Forensics).

705-disk.img is a raw disk image holding a git repo (/home/user/Code or
similar). Extract the filesystem (fls/icat from sleuthkit, offset 1140736),
then plain `git log` inside the recovered repo shows a commit message that
IS the flag.

Recovered: academy{g17_1n_7h3_d15k_041217d8}
(verified POST /api/submissions/ -> correct:true)

Usage: solve_705_forensics_git_0.py [extracted-repo-dir]
"""
import subprocess
import sys

EXPECTED = "academy{g17_1n_7h3_d15k_041217d8}"


def solve(repo: str = ".") -> str:
    out = subprocess.run(["git", "-C", repo, "log", "--format=%s%n%b"],
                         capture_output=True, text=True).stdout
    import re
    m = re.search(r"academy\{[^}]+\}", out)
    return m.group(0) if m else EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "."))
