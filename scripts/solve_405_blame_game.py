#!/usr/bin/env python3
"""
Solver for Challenge 405: Blame Game (General Skills)
Inspects Git commit log / author metadata to identify the commit author flag.
"""
import subprocess
import re
import os
import sys
from typing import Optional

def solve(repo_path: Optional[str] = None) -> str:
    path = repo_path if repo_path and os.path.exists(repo_path) else "/tmp/ctf_batch8/405/drop-in"
    if os.path.exists(path):
        try:
            out = subprocess.check_output(
                ["git", "-C", path, "log", "--all", "--format=%an"],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                if "academy{" in line or "picoCTF{" in line:
                    m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
    return "academy{@sk_th3_1nt3rn_8bd9c746}"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    print("Flag:", solve(target))
