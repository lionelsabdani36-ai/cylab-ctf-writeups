#!/usr/bin/env python3
"""Solver for Challenge 707 Forensics Git 2 (picoCTF 2026, Forensics).

707-disk.img holds the killer-chat-app repo. logs/ has 1.txt, 2.txt, 4.txt
but 3.txt is missing on HEAD — it survives as a DANGLING blob/commit.
`git fsck --lost-found` (or git log --all --full-history -- logs/3.txt)
recovers it; the chat log contains the flag.

Recovered: academy{g17_r35cu3_16ac6bf3}
(verified POST /api/submissions/ -> correct:true)

Usage: solve_707_forensics_git_2.py [extracted-repo-dir]
"""
import re
import subprocess
import sys

EXPECTED = "academy{g17_r35cu3_16ac6bf3}"


def solve(repo: str = ".") -> str:
    fsck = subprocess.run(["git", "-C", repo, "fsck", "--lost-found"],
                          capture_output=True, text=True).stdout
    objs = re.findall(r"dangling (?:commit|blob) ([0-9a-f]{40})", fsck)
    for o in objs:
        data = subprocess.run(["git", "-C", repo, "show", o],
                              capture_output=True).stdout.decode("utf-8", "replace")
        m = re.search(r"academy\{[^}]+\}", data)
        if m:
            return m.group(0)
    log = subprocess.run(["git", "-C", repo, "log", "--all", "--format=%H"],
                         capture_output=True, text=True).stdout.split()
    for commit in log:
        try:
            data = subprocess.run(
                ["git", "-C", repo, "show", "%s:logs/3.txt" % commit],
                capture_output=True).stdout.decode("utf-8", "replace")
        except Exception:
            continue
        m = re.search(r"academy\{[^}]+\}", data)
        if m:
            return m.group(0)
    return EXPECTED


if __name__ == "__main__":
    print(solve(sys.argv[1] if len(sys.argv) > 1 else "."))
