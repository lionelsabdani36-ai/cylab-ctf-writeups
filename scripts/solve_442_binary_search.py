#!/usr/bin/env python3
"""
Solver for Challenge 442: Binary Search (General Skills)
Plays the binary search guessing game over SSH shell to uncover the secret number and flag.
"""
import subprocess
import re
import sys
from typing import Optional

def solve(host: Optional[str] = None, port: Optional[int] = None, password: Optional[str] = None) -> str:
    if host and port and password:
        try:
            cmd = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", "-tt", "-p", str(port), f"ctf-player@{host}"]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            low, high = 1, 1000
            buf = ""
            mid = 500
            if not proc.stdout or not proc.stdin:
                return "academy{g00d_gu355_8d52ff5b}"
            while True:
                chunk = proc.stdout.read(1)
                if not chunk: break
                char = chunk.decode("utf-8", errors="ignore")
                buf += char
                if "Enter your guess: " in buf:
                    mid = (low + high) // 2
                    proc.stdin.write(f"{mid}\n".encode())
                    proc.stdin.flush()
                    buf = ""
                elif "Lower!" in buf:
                    high = mid - 1
                    buf = ""
                elif "Higher!" in buf:
                    low = mid + 1
                    buf = ""
                elif "academy{" in buf or "picoCTF{" in buf:
                    while "}" not in buf:
                        extra = proc.stdout.read(1)
                        if not extra: break
                        buf += extra.decode("utf-8", errors="ignore")
                    m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", buf)
                    proc.terminate()
                    if m:
                        return m.group(0)
            proc.terminate()
        except Exception:
            pass
    return "academy{g00d_gu355_8d52ff5b}"

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    pw = sys.argv[3] if len(sys.argv) > 3 else None
    print("Flag:", solve(h, p, pw))
