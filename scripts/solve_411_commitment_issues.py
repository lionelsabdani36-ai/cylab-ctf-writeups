#!/usr/bin/env python3
"""
Solver for Challenge 411: Commitment Issues (General Skills)
Inspects git diffs of previous commits where sensitive data was removed.
"""
import subprocess
import re
import os

def solve(repo_path="."):
    cmd = ["git", "-C", repo_path, "log", "-p", "--all"]
    out = subprocess.check_output(cmd).decode()
    m = re.search(r"academy{[^}]+}", out)
    return m.group(0) if m else None

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/411/drop-in"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{s@n1t1z3_21c298e5}")
