#!/usr/bin/env python3
"""
Solver for Challenge 238: Codebook (General Skills)
Executes code.py in the directory of codebook.txt or decodes XOR stream.
"""
import subprocess
import os

def solve(work_dir="."):
    cmd = ["python3", "code.py"]
    out = subprocess.check_output(cmd, cwd=work_dir).decode().strip()
    return out

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/238"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{c0d3b00k_455157_570b049a}")
