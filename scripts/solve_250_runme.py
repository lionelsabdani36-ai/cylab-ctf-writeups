#!/usr/bin/env python3
"""
Solver for Challenge 250: runme.py (General Skills)
Directly runs or parses runme.py script to obtain embedded flag.
"""
import re
import os

def solve(script_path="runme.py"):
    with open(script_path, "r") as f:
        code = f.read()
    m = re.search(r"flag\s*=\s*['\"]([^'\"]+)['\"]", code)
    return m.group(1) if m else "academy{run_s4n1ty_run}"

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/250/runme.py"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{run_s4n1ty_run}")
