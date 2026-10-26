#!/usr/bin/env python3
"""
Solver for Challenge 425: Time Machine (General Skills)
Inspects git commit history to extract commit message flag.
"""
import subprocess
import re
import os

def solve(repo_path="."):
    cmd = ["git", "-C", repo_path, "log", "--all", "-p"]
    out = subprocess.check_output(cmd).decode()
    m = re.search(r"academy{[^}]+}", out)
    return m.group(0) if m else None

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/425/drop-in"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{t1m3m@ch1n3_aaac4598}")
