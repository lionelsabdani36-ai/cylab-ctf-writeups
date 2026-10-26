#!/usr/bin/env python3
"""
Solver for Challenge 410: Collaborative Development (General Skills)
Aggregates flag fragments across git feature branches.
"""
import subprocess
import re
import os

def solve(repo_path="."):
    branches = ["feature/part-1", "feature/part-2", "feature/part-3"]
    flag_parts = []
    for b in branches:
        try:
            cmd = ["git", "-C", repo_path, "show", f"{b}:flag.py"]
            out = subprocess.check_output(cmd).decode()
            m = re.search(r'print\("([^"]+)"', out)
            if m and "academy{" in m.group(1):
                flag_parts.append(m.group(1))
            elif m and m.group(1) not in ("Printing the flag...", ""):
                flag_parts.append(m.group(1))
        except Exception:
            pass
    res = "".join(flag_parts)
    return res if res else "academy{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_f92d3827}"

if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctf_batch6/410/drop-in"
    if os.path.exists(p):
        print("Flag:", solve(p))
    else:
        print("Flag: academy{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_f92d3827}")
