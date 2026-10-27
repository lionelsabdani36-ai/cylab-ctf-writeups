#!/usr/bin/env python3
"""
Solver for Challenge 12: vault-door-1 (Reverse Engineering)
Reconstructs password by parsing index assertions in VaultDoor1.java.
"""
import urllib.request
import re

def solve(url: str = "https://challenge-files.cylabacademy.net/library/dd0ae9b406943de9f8bee5c8f5b509e72ad86fc3855bbe2f4f83228d6309a25c/VaultDoor1.java") -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    content = urllib.request.urlopen(req).read().decode()
    matches = re.findall(r"password\.charAt\((\d+)\)\s*==\s*'([^']*)'", content)
    flag_chars = {}
    for idx, ch in matches:
        flag_chars[int(idx)] = ch
    inner = "".join(flag_chars[i] for i in range(len(flag_chars)))
    return f"academy{{{inner}}}"

if __name__ == "__main__":
    print("Flag:", solve())
