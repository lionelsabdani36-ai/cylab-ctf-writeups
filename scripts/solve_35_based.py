"""Solver for challenge 35 Based (picoCTF 2019, General Skills).

Three-stage nc service: stage 1 answers a binary-encoded word, stage 2 an
octal-encoded word, stage 3 a hex-encoded word (tokens may be multi-byte, so
digits are joined then split every 2 chars before bytes.fromhex).

Usage: solve_35_based.py <host> <port>
"""
import re
import socket
import sys


def runtil(f, marker: bytes) -> bytes:
    data = b''
    while marker not in data:
        chunk = f.read(1)
        if not chunk:
            break
        data += chunk
    return data


def solve(host: str, port: int) -> str:
    s = socket.create_connection((host, port), timeout=15)
    f = s.makefile('rwb', buffering=0)
    runtil(f, b'2)')
    # Stage 1: binary
    data = runtil(f, b'Input:').decode(errors='replace')
    word = re.findall(r'[01]{8}(?: [01]{8})*', data)[-1]
    ans = ''.join(chr(int(b, 2)) for b in word.split())
    f.write(ans.encode() + b'\n')
    # Stage 2: octal
    data = runtil(f, b'Input:').decode(errors='replace')
    word = re.findall(r'[0-7]{3}(?: [0-7]{3})*', data)[-1]
    ans = ''.join(chr(int(o, 8)) for o in word.split())
    f.write(ans.encode() + b'\n')
    # Stage 3: hex (tokens may be 10 chars -> join then split per 2)
    data = runtil(f, b'Input:').decode(errors='replace')
    toks = re.findall(r'[0-9a-fA-F]{2,}', data)
    blob = ''.join(t for t in toks if len(t) >= 2)
    ans = bytes.fromhex(blob).decode()
    f.write(ans.encode() + b'\n')
    out = b''
    try:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > 8192:
                break
    except Exception:
        pass
    s.close()
    m = re.search(rb'academy\{[^}]+\}', out)
    return m.group(0).decode() if m else out.decode(errors='replace')


if __name__ == '__main__':
    print(solve(sys.argv[1], int(sys.argv[2])))
