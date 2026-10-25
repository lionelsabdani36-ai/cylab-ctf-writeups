#!/usr/bin/env python3
"""
Solver for Challenge 727: Quizploit (Binary Exploitation)
Automated interactive client for binary mitigation & ELF analysis quiz.
"""
import socket
import re

ANSWERS = [
    '64-bit',
    'dynamic',
    'not stripped',
    '0x15',
    '0x90',
    'yes',
    'fgets',
    'win',
    'buffer overflow',
    '0x7b',
    'NX',
    'ROP',
    '0x401176'
]

def solve(host, port):
    s = socket.socket()
    s.connect((host, int(port)))
    s.settimeout(5)

    for ans in ANSWERS:
        buf = ''
        while True:
            chunk = s.recv(1024).decode('utf-8', errors='ignore')
            buf += chunk
            if '>>' in buf or 'academy{' in buf:
                break
        s.sendall(f'{ans}
'.encode())

    final_buf = ''
    while True:
        try:
            chunk = s.recv(1024).decode('utf-8', errors='ignore')
            if not chunk: break
            final_buf += chunk
        except socket.timeout:
            break

    s.close()
    m = re.search(r'academy{[^}]+}', final_buf)
    return m.group(0) if m else final_buf

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('Usage: python3 solve_727_quizploit.py <host> <port>')
        print('Known Flag: academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}')
    else:
        print('Flag:', solve(sys.argv[1], sys.argv[2]))
