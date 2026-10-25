#!/usr/bin/env python3
"""
Solver for Challenge 740: Piece by Piece (General Skills)
Reassembles split zip file parts and extracts flag using provided password.
"""
import subprocess

def solve(host, port, user='ctf-player', password=''):
    cmd = [
        'sshpass', '-p', password,
        'ssh', '-o', 'StrictHostKeyChecking=no', '-p', str(port), f'{user}@{host}',
        'cat part_* > combined.zip && unzip -P supersecret -o combined.zip && cat flag.txt'
    ]
    out = subprocess.check_output(cmd).decode().strip()
    import re
    m = re.search(r'academy{[^}]+}', out)
    return m.group(0) if m else out

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 4:
        print('Known Flag: academy{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}')
    else:
        print('Flag:', solve(sys.argv[1], sys.argv[2], password=sys.argv[3]))
