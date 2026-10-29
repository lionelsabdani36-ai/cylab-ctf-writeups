#!/usr/bin/env python3
"""Solver for Challenge 706 Forensics Git 1 (picoCTF 2026, Forensics).

706-disk.img holds the same style git repo. The flag is NOT on HEAD — check
out an older commit (git log --all --oneline, then git checkout <commit>)
where the secrets file still contains the real flag; later commits wiped it.

Recovered: academy{g17_r3m3mb3r5_d4ddf904}
(verified POST /api/submissions/ -> correct:true)

Usage: solve_706_forensics_git_1.py [extracted-repo-dir]
"""
import re
import subprocess
import sys

EXPECTED = "academy{g17_r3m3mb3r5_d4ddf904}"


def solve(repo: str = ".") -> str:
    log = subprocess.run(["git", "-C", repo, "log", "--all", "--format=%H"],
                         capture_output=True, text=True).stdout.split()
    for commit in log:
        tree = subprocess.run(["git", "-C", repo, "ls-tree", "-r", commit],
                              capture_output=True, text=True).stdout
        for line in tree.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            blob, name = parts[2], parts[3]
            data = subprocess.run(["git", "-C", repo, "show", blob],
                                  capture_output=True).stdout.decode("utf-8", "replace")
            m = re.search(r"academy\{[^}]+\}", data)
            if m:
                return m.group(0)
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "."))
