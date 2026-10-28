"""Solver for challenge 38 waves over lambda (picoCTF 2019, Cryptography).

Monoalphabetic substitution service. The cracked key below was derived via a
crib (ciphertext always opens with a title decoding to 'congrats here is your
flag - frequency_is_c_over_lambda_...') plus dictionary hill-climbing.

NOTE: the accepted flag is the RAW string without braces: submitting
academy{...} / picoCTF{...} / flag{...} variants returns correct:false.

Usage: solve_38_waves_over_lambda.py <host> <port>
"""
import re
import socket
import sys

# cipher-letter -> plain-letter (cracked, verified on 3 independent sessions)
KEY = dict(zip('nqvhkurdmxefwactbslzgpyioj', 'abcdefghijklmnopqrstuvwxyz'))


def decode(ct: str) -> str:
    out = []
    for ch in ct:
        if 'a' <= ch <= 'z':
            out.append(KEY[ch])
        else:
            out.append(ch)
    return ''.join(out)


def solve(host: str, port: int) -> str:
    s = socket.create_connection((host, port), timeout=15)
    f = s.makefile('rwb', buffering=0)
    data = b''
    try:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
    except Exception:
        pass
    s.close()
    text = data.decode(errors='replace')
    m = re.findall(r'[a-z_]{200,}', text)
    if not m:
        return text
    return decode(max(m, key=len))


if __name__ == '__main__':
    print(solve(sys.argv[1], int(sys.argv[2])))
