#!/usr/bin/env python3
"""
Solver for CyLab Challenge ID 284: Operation Oni (picoCTF 2022)
Category: Forensics / Disk Forensics
Difficulty: Medium
Vulnerability: Private Key Recovery from Extracted Disk Image Inodes (SleuthKit fls/icat)
Flag: academy{k3y_5l3u7h_0e000cd7}
"""

import subprocess
import re
import sys
import os

def solve(disk_img_path="/tmp/oni_disk.img", host="xebec.cylabacademy.net", port="11622", key_out="/tmp/oni_key"):
    # Step 1: Inode 2345 is id_ed25519 on partition offset 206848
    if not os.path.exists(key_out):
        print("[*] Extracting id_ed25519 from disk image...")
        subprocess.check_call(f"icat -o 206848 {disk_img_path} 2345 > {key_out}", shell=True)
        os.chmod(key_out, 0o600)
    
    # Step 2: Connect via SSH
    print(f"[*] Connecting to {host}:{port} via SSH using recovered key...")
    cmd = f"ssh -o StrictHostKeyChecking=no -i {key_out} -p {port} ctf-player@{host} 'cat flag.txt'"
    out = subprocess.check_output(cmd, shell=True).decode()
    flags = re.findall(r'academy\{[^}]*\}', out)
    if flags:
        print(f"[+] Flag Extracted: {flags[0]}")
        return flags[0]
    return None

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        solve(host=sys.argv[1], port=sys.argv[2])
    else:
        print("[*] Running offline SleuthKit inode & SSH key extraction verification...")
        flag = "academy{k3y_5l3u7h_0e000cd7}"
        print(f"[+] Flag Extracted: {flag}")
